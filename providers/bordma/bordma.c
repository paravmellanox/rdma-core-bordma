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

static const struct verbs_context_ops bordma_context_ops; 
struct bordma_device {
	struct verbs_device base_dev;
};

struct bordma_context {
	struct verbs_context base_ctx;
	int a;
	int b;
};

static inline struct bordma_context *ctx_ibv2bordma(struct ibv_context *base)
{
	return container_of(base, struct bordma_context, base_ctx.context);
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

	ctx = verbs_init_and_alloc_context(base_dev, fd, ctx, base_ctx, 21);
	if (!ctx)
		return NULL;

	if (ibv_cmd_get_context(&ctx->base_ctx, &cmd, sizeof(cmd),
				NULL, &rsp.rsp, sizeof(rsp))) {
		verbs_uninit_context(&ctx->base_ctx);
		free(ctx);
		return NULL;
	}

	verbs_set_ops(&ctx->base_ctx, &bordma_context_ops);

	return &ctx->base_ctx;
}

static void bordma_free_context(struct ibv_context *ibv_ctx)
{
	struct bordma_context *ctx = ctx_ibv2bordma(ibv_ctx);

	verbs_uninit_context(&ctx->base_ctx);
	free(ctx);
}

static const struct verbs_context_ops bordma_context_ops = {
	.query_device_ex = bordma_query_device,
	.query_port = bordma_query_port,
	.free_context = bordma_free_context,
	#if 0
	.alloc_pd = bordma_alloc_pd,
	.async_event = bordma_async_event,
	.create_cq = bordma_create_cq,
	.create_qp = bordma_create_qp,
	.create_srq = bordma_create_srq,
	.dealloc_pd = bordma_free_pd,
	.dereg_mr = bordma_dereg_mr,
	.destroy_cq = bordma_destroy_cq,
	.destroy_qp = bordma_destroy_qp,
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
