#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <net/if.h>
#include <pthread.h>
#include <stdatomic.h>
#include <assert.h>

#include <infiniband/driver.h>
#include <infiniband/kern-abi.h>
#include <infiniband/verbs.h>

#define NUM_BACKEND_QP 4         /* Number of backend QPs per frontend QP */
#define BACKEND_DEVICE_NAME "mlx5_0"  /* Real backend device to use */

static const struct verbs_context_ops bordma_context_ops; 
struct bordma_device {
	struct verbs_device base_dev;
};

struct bordma_context {
	struct verbs_context base_ctx;     /* Frontend context (what user sees) */
	struct ibv_context *backend_ctx;   /* Backend device context (real device) */
};

struct bordma_pd {
	struct ibv_pd ibv_pd;              /* Frontend PD (what user sees) */
	struct ibv_pd *backend_pd;         /* Backend PD on real device */
};

struct bordma_qp {
	struct verbs_qp verbs_qp;          /* Frontend QP */
	struct ibv_qp **backend_qps;       /* Array of backend QPs */
	struct ibv_cq *shared_cq;          /* Shared CQ for all backend QPs */
	struct ibv_pd *backend_pd;         /* Backend protection domain */
	int num_backend_qps;               /* Number of backend QPs created */
};

static inline struct bordma_context *ctx_ibv2bordma(struct ibv_context *base)
{
	return container_of(base, struct bordma_context, base_ctx.context);
}

static inline struct bordma_pd *pd_ibv2bordma(struct ibv_pd *base)
{
	return container_of(base, struct bordma_pd, ibv_pd);
}

static inline struct bordma_qp *qp_ibv2bordma(struct ibv_qp *base)
{
	return container_of(base, struct bordma_qp, verbs_qp.qp);
}


static int bordma_query_device(struct ibv_context *context,
			 const struct ibv_query_device_ex_input *input,
			 struct ibv_device_attr_ex *attr, size_t attr_size)
{
	snprintf(attr->orig_attr.fw_ver, sizeof(attr->orig_attr.fw_ver),
		 "%d.%d.%d", 0, 1, 0);

	return 0;
}

static int bordma_query_port(struct ibv_context *ctx, uint8_t port,
			  struct ibv_port_attr *attr)
{
	attr->max_mtu = IBV_MTU_1024;
	return 0;
}

static struct verbs_device *bordma_device_alloc(struct verbs_sysfs_dev *unused)
{
	struct bordma_device *dev;

	dev = calloc(1, sizeof(*dev));
	if (!dev)
		return NULL;

	return &dev->base_dev;
}

static void bordma_device_free(struct verbs_device *vdev)
{
	struct bordma_device *dev =
		container_of(vdev, struct bordma_device, base_dev);
	free(dev);
}

struct bordma_alloc_ctx_rsp {
	struct ib_uverbs_get_context_resp rsp;
	int a;
	int b;
};

static struct verbs_context *bordma_alloc_context(struct ibv_device *base_dev,
					       int fd, void *pdata)
{
	struct bordma_context *ctx;
	struct ibv_get_context cmd = {};
	struct bordma_alloc_ctx_rsp rsp;
	struct ibv_device **device_list;
	int num_devices, i;

	/* Allocate frontend context */
	ctx = verbs_init_and_alloc_context(base_dev, fd, ctx, base_ctx, 21);
	if (!ctx)
		return NULL;

	if (ibv_cmd_get_context(&ctx->base_ctx, &cmd, sizeof(cmd),
				NULL, &rsp.rsp, sizeof(rsp))) {
		verbs_uninit_context(&ctx->base_ctx);
		free(ctx);
		return NULL;
	}

	/* Open backend device for actual RDMA operations */
	device_list = ibv_get_device_list(&num_devices);
	if (!device_list) {
		fprintf(stderr, "Failed to get RDMA device list\n");
		goto err_free_frontend;
	}

	ctx->backend_ctx = NULL;
	for (i = 0; i < num_devices; i++) {
		if (strcmp(ibv_get_device_name(device_list[i]), BACKEND_DEVICE_NAME) == 0) {
			ctx->backend_ctx = ibv_open_device(device_list[i]);
			if (ctx->backend_ctx) {
				printf("Opened backend device: %s\n", BACKEND_DEVICE_NAME);
				break;
			}
		}
	}
	ibv_free_device_list(device_list);

	if (!ctx->backend_ctx) {
		fprintf(stderr, "Failed to open backend device %s\n", BACKEND_DEVICE_NAME);
		goto err_free_frontend;
	}

	verbs_set_ops(&ctx->base_ctx, &bordma_context_ops);

	return &ctx->base_ctx;

err_free_frontend:
	verbs_uninit_context(&ctx->base_ctx);
	free(ctx);
	return NULL;
}

static void bordma_free_context(struct ibv_context *ibv_ctx)
{
	struct bordma_context *ctx = ctx_ibv2bordma(ibv_ctx);

	/* Close backend device */
	if (ctx->backend_ctx) {
		ibv_close_device(ctx->backend_ctx);
		printf("Closed backend device\n");
	}

	/* Free frontend context */
	verbs_uninit_context(&ctx->base_ctx);
	free(ctx);
}

static struct ibv_pd *bordma_alloc_pd(struct ibv_context *ibv_ctx)
{
	struct bordma_context *ctx = ctx_ibv2bordma(ibv_ctx);
	struct bordma_pd *pd;

	printf("Allocating PD: Frontend device=%s, Backend device=%s\n",
	       ibv_get_device_name(ibv_ctx->device),
	       ibv_get_device_name(ctx->backend_ctx->device));

	/* Allocate bordma PD structure */
	pd = calloc(1, sizeof(*pd));
	if (!pd)
		return NULL;

	/* Allocate backend PD from real device */
	pd->backend_pd = ibv_alloc_pd(ctx->backend_ctx);
	if (!pd->backend_pd) {
		fprintf(stderr, "Failed to allocate backend PD from %s\n",
			ibv_get_device_name(ctx->backend_ctx->device));
		free(pd);
		return NULL;
	}

	printf("Allocated backend PD on %s (handle: %d)\n",
	       ibv_get_device_name(ctx->backend_ctx->device),
	       pd->backend_pd->handle);

	/* Initialize frontend PD */
	pd->ibv_pd.context = ibv_ctx;

	return &pd->ibv_pd;
}

static int bordma_free_pd(struct ibv_pd *ibv_pd)
{
	struct bordma_pd *pd = pd_ibv2bordma(ibv_pd);
	int ret = 0;

	printf("Freeing PD\n");

	/* Free backend PD */
	if (pd->backend_pd) {
		ret = ibv_dealloc_pd(pd->backend_pd);
		if (ret) {
			fprintf(stderr, "Failed to deallocate backend PD: %d\n", ret);
		} else {
			printf("Deallocated backend PD\n");
		}
	}

	/* Free frontend PD structure */
	free(pd);

	return ret;
}

static struct ibv_qp *bordma_create_qp(struct ibv_pd *pd,
					struct ibv_qp_init_attr *attr)
{
	struct ibv_create_qp cmd = {};
	struct ib_uverbs_create_qp_resp resp = {};
	struct bordma_context *ctx;
	struct bordma_pd *bordma_pd;
	struct bordma_qp *qp;
	struct ibv_qp_init_attr backend_attr;
	int ret, i;

	/* Get bordma context and PD to access backend resources */
	ctx = ctx_ibv2bordma(pd->context);
	bordma_pd = pd_ibv2bordma(pd);

	printf("Creating QP: Frontend device=%s, Backend device=%s\n",
	       ibv_get_device_name(pd->context->device),
	       ibv_get_device_name(ctx->backend_ctx->device));

	/* Allocate QP structure */
	qp = calloc(1, sizeof(*qp));
	if (!qp)
		return NULL;

	/* Allocate array for backend QPs */
	qp->backend_qps = calloc(NUM_BACKEND_QP, sizeof(struct ibv_qp *));
	if (!qp->backend_qps) {
		free(qp);
		return NULL;
	}

	/* Create frontend QP (dummy, for compatibility) */
	ret = ibv_cmd_create_qp(pd, &qp->verbs_qp.qp, attr,
				&cmd, sizeof(cmd),
				&resp, sizeof(resp));
	if (ret)
		goto err_free_backend_array;

	/* Store backend PD (from real device) */
	qp->backend_pd = bordma_pd->backend_pd;

	/* Create shared CQ on BACKEND device */
	qp->shared_cq = ibv_create_cq(ctx->backend_ctx, 
				      attr->cap.max_send_wr * NUM_BACKEND_QP + 
				      attr->cap.max_recv_wr * NUM_BACKEND_QP,
				      NULL, NULL, 0);
	if (!qp->shared_cq) {
		fprintf(stderr, "Failed to create shared CQ on backend device\n");
		goto err_destroy_frontend_qp;
	}
	printf("Created shared CQ on backend device (handle: %d)\n", qp->shared_cq->handle);

	/* Prepare backend QP attributes */
	memcpy(&backend_attr, attr, sizeof(backend_attr));
	backend_attr.send_cq = qp->shared_cq;
	backend_attr.recv_cq = qp->shared_cq;

	/* Create NUM_BACKEND_QP backend QPs on REAL device, all using shared CQ */
	for (i = 0; i < NUM_BACKEND_QP; i++) {
		qp->backend_qps[i] = ibv_create_qp(bordma_pd->backend_pd, &backend_attr);
		if (!qp->backend_qps[i]) {
			fprintf(stderr, "Failed to create backend QP %d/%d on %s\n", 
				i + 1, NUM_BACKEND_QP, ibv_get_device_name(ctx->backend_ctx->device));
			goto err_destroy_backend_qps;
		}
		qp->num_backend_qps++;
		printf("Created backend QP %d/%d on %s (QPN: %d)\n", 
		       i + 1, NUM_BACKEND_QP, ibv_get_device_name(ctx->backend_ctx->device),
		       qp->backend_qps[i]->qp_num);
	}

	/* Set initial QP state */
	qp->verbs_qp.qp.state = IBV_QPS_RESET;

	printf("Successfully created bordma QP with %d backend QPs on %s\n",
	       NUM_BACKEND_QP, ibv_get_device_name(ctx->backend_ctx->device));

	return &qp->verbs_qp.qp;

err_destroy_backend_qps:
	/* Destroy any backend QPs that were created */
	for (i = 0; i < qp->num_backend_qps; i++) {
		if (qp->backend_qps[i])
			ibv_destroy_qp(qp->backend_qps[i]);
	}
	ibv_destroy_cq(qp->shared_cq);
err_destroy_frontend_qp:
	ibv_cmd_destroy_qp(&qp->verbs_qp.qp);
err_free_backend_array:
	free(qp->backend_qps);
	free(qp);
	return NULL;
}

static int bordma_destroy_qp(struct ibv_qp *ibqp)
{
	struct bordma_qp *qp = qp_ibv2bordma(ibqp);
	int ret, i;

	printf("Destroying bordma QP with %d backend QPs\n", qp->num_backend_qps);

	/* Destroy all backend QPs */
	for (i = 0; i < qp->num_backend_qps; i++) {
		if (qp->backend_qps[i]) {
			ret = ibv_destroy_qp(qp->backend_qps[i]);
			if (ret) {
				fprintf(stderr, "Failed to destroy backend QP %d: %d\n", 
					i, ret);
			} else {
				printf("Destroyed backend QP %d/%d\n", 
				       i + 1, qp->num_backend_qps);
			}
		}
	}

	/* Destroy the shared CQ */
	if (qp->shared_cq) {
		ret = ibv_destroy_cq(qp->shared_cq);
		if (ret) {
			fprintf(stderr, "Failed to destroy shared CQ: %d\n", ret);
		} else {
			printf("Destroyed shared CQ\n");
		}
	}

	/* Destroy the frontend QP in kernel */
	ret = ibv_cmd_destroy_qp(ibqp);
	if (ret)
		fprintf(stderr, "Failed to destroy frontend QP: %d\n", ret);

	/* Free allocated memory */
	free(qp->backend_qps);
	free(qp);

	return ret;
}

static const struct verbs_context_ops bordma_context_ops = {
	.query_device_ex = bordma_query_device,
	.query_port = bordma_query_port,
	.free_context = bordma_free_context,
	.alloc_pd = bordma_alloc_pd,
	.dealloc_pd = bordma_free_pd,
	.create_qp = bordma_create_qp,
	.destroy_qp = bordma_destroy_qp,
	#if 0
	.async_event = bordma_async_event,
	.create_cq = bordma_create_cq,
	.create_srq = bordma_create_srq,
	.dereg_mr = bordma_dereg_mr,
	.destroy_cq = bordma_destroy_cq,
	.destroy_srq = bordma_destroy_srq,
	.modify_qp = bordma_modify_qp,
	.modify_srq = bordma_modify_srq,
	.poll_cq = bordma_poll_cq,
	.post_recv = bordma_post_recv,
	.post_send = bordma_post_send,
	.post_srq_recv = bordma_post_srq_recv,
	.query_qp = bordma_query_qp,
	.reg_mr = bordma_reg_mr,
	.req_notify_cq = bordma_notify_cq,
	#endif
};

static const struct verbs_match_ent match_table[] = {
	VERBS_DRIVER_ID(RDMA_DRIVER_BORDMA),
	{},
};

static const struct verbs_device_ops bordma_dev_ops = {
	.name = "bordma",
	.match_min_abi_version = 0,
	.match_max_abi_version = 0,
	.match_table = match_table,
	.alloc_device = bordma_device_alloc,
	.uninit_device = bordma_device_free,
	.alloc_context = bordma_alloc_context,
};

PROVIDER_DRIVER(bordma, bordma_dev_ops);
