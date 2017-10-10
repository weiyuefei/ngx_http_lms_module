
/*
 * Copyright (C) SDMC ltd.
 * Author:       feeman
 */

#include <stdio.h>
#include <unistd.h>
#include <dirent.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#include <assert.h>
#include <fnmatch.h>

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "libavformat/avformat.h"
#include "libavutil/avutil.h"
#include "libavcodec/avcodec.h"

typedef struct ngx_http_lms_list_node_t ngx_http_lms_list_node_t;

typedef struct {
    ngx_shm_zone_t *shm_zone;
} ngx_http_lms_loc_conf_t;

typedef struct {
    ngx_http_lms_list_node_t *cached_head;
    ngx_slab_pool_t          *shpool;
} ngx_http_lms_ctx_t;

struct ngx_http_lms_list_node_t {
    ngx_int_t    vist_count;  // 统计访问次数
    ngx_str_t    playlist; // 索引文件内容
    ngx_str_t    key_cmp; // 比较的key值

    // 在插入一个节点的时候，如果有节点已经达到老化时间，则使用该节点进行缓存
    time_t       expire_time; // 是否达到老化时间
    time_t       start_time; // 第一次缓存时间

    ngx_http_lms_list_node_t *next;
};

#define NGX_HTTP_LMS_START          0
#define NGX_HTTP_LMS_HEAD_CONST     0
#define NGX_HTTP_LMS_HEAD_VERSION   1
#define NGX_HTTP_LMS_HEAD_DURATION  2
#define NGX_HTTP_LMS_FRAGMENT_LIST  3
#define NGX_HTTP_LMS_ENDLIST        4
#define NGX_HTTP_LMS_END            5

typedef struct {
    ngx_int_t   type;
    char       *fmt_str;
} ngx_http_lms_playlist_item_t;

static ngx_http_lms_playlist_item_t ngx_http_lms_playlist_item[] = {

    { NGX_HTTP_LMS_HEAD_CONST,
      "#EXTM3U\n#EXT-X-MEDIA-SEQUENCE:0\n#EXT-X-ALLOW-CACHE:YES\n" },

    { NGX_HTTP_LMS_HEAD_VERSION,
      "#EXT-X-VERSION:%d\n" },

    { NGX_HTTP_LMS_HEAD_DURATION,
      "#EXT-X-TARGETDURATION:%d\n" },

    { NGX_HTTP_LMS_FRAGMENT_LIST,
      "#EXTINF:%.2f,\nhls/fragment%d.ts\n" },

    { NGX_HTTP_LMS_ENDLIST,
      "#EXT-X-ENDLIST\n" },

    { -1, NULL }
};

static char *
    ngx_http_lms(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t
    ngx_http_lms_handler(ngx_http_request_t *r);
static void*
    ngx_http_lms_create_loc_conf(ngx_conf_t* cf);
static char *
    ngx_http_lms_merge_loc_conf(ngx_conf_t* cf, void* parent, void* child);
static ngx_int_t
    ngx_http_lms_init_zone(ngx_shm_zone_t *shm_zone, void *data);
static char *
    ngx_http_lms_cached_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t
    ngx_http_lms_init_worker(ngx_cycle_t *cycle);

static ngx_int_t
    ngx_http_lms_send_data(ngx_http_request_t *r, ngx_chain_t *out);
static ngx_http_lms_list_node_t *
    ngx_http_lms_list_lookup(ngx_http_request_t *r, ngx_http_lms_ctx_t *ctx);
static ngx_str_t
    ngx_http_lms_get_playlist(ngx_http_request_t *r);
static ngx_http_lms_list_node_t *
    ngx_http_lms_create_playlist(ngx_http_request_t *r, ngx_http_lms_ctx_t *ctx);
static ngx_int_t
    ngx_http_lms_list_insert(ngx_http_request_t *r, ngx_http_lms_ctx_t *ctx, ngx_http_lms_list_node_t *node);


static ngx_command_t ngx_http_lms_commands[] = {
	{ 	ngx_string("lms"),
		NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
		ngx_http_lms,
		0,
		0,
		NULL },

    { ngx_string("lms_cached_zone"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE12,
      ngx_http_lms_cached_zone,
      0,
      0,
      NULL
    },

	ngx_null_command
};


static ngx_http_module_t ngx_http_lms_module_ctx = {
    NULL,                          /* preconfiguration */
    NULL,                          /* postconfiguration */

    NULL,                          /* create main configuration */
    NULL,                          /* init main configuration */

    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */

    ngx_http_lms_create_loc_conf,  /* create location configuration */
    ngx_http_lms_merge_loc_conf    /* merge location configuration */
};


ngx_module_t ngx_http_lms_module = {
    NGX_MODULE_V1,
    &ngx_http_lms_module_ctx,      /* module context */
    ngx_http_lms_commands,         /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    ngx_http_lms_init_worker,      /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_lms_handler(ngx_http_request_t *r)
{
	ngx_int_t                  ret;
	ngx_chain_t                out;
    ngx_buf_t                 *b;
    ngx_http_lms_ctx_t        *ctx;
    ngx_http_lms_loc_conf_t   *llcf;

	if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
		return NGX_HTTP_NOT_ALLOWED;
	}

	if (r->uri.data[r->uri.len - 1] == '/') {
		return NGX_DECLINED;
	}

	ret = ngx_http_discard_request_body(r);

	if (ret != NGX_OK) {
		return ret;
	}

    ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, ngx_errno,
                 "Request line: [%V], worker pid = %d",
                  &r->request_line, ngx_getpid());

    llcf = ngx_http_get_module_loc_conf(r, ngx_http_lms_module);

    ctx = llcf->shm_zone->data;
    ctx->shpool = (ngx_slab_pool_t *) llcf->shm_zone->shm.addr;

    ngx_shmtx_lock(&ctx->shpool->mutex);

	ngx_http_lms_list_node_t *node = ngx_http_lms_list_lookup(r, ctx);

	if (node == NULL) {

        node = ngx_http_lms_create_playlist(r, ctx);
        if (node == NULL) {
            ngx_shmtx_unlock(&ctx->shpool->mutex);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_http_lms_list_insert(r, ctx, node);
	}

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) {
        ngx_shmtx_unlock(&ctx->shpool->mutex);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->start = ngx_pcalloc(r->pool, node->playlist.len);
    if (b->start == NULL) {
        ngx_shmtx_unlock(&ctx->shpool->mutex);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    b->pos = b->start;
    b->last = b->pos + node->playlist.len;
    ngx_memcpy(b->pos, node->playlist.data, node->playlist.len);

    b->memory = 1;
    b->last_buf = (r == r->main) ? 1: 0;

    out.buf = b;
    out.next = NULL;

    ngx_shmtx_unlock(&ctx->shpool->mutex);

	return ngx_http_lms_send_data(r,&out);
}


static ngx_int_t
ngx_http_lms_send_data(ngx_http_request_t *r, ngx_chain_t *out)
{
	ngx_int_t  rc;

	r->headers_out.status = NGX_HTTP_OK;
	r->headers_out.content_length_n = ngx_buf_size(out->buf);

	if (ngx_http_set_content_type(r) != NGX_OK) {
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	rc = ngx_http_send_header(r);

	if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
		return rc;
	}

	return ngx_http_output_filter(r, out);
}

static ngx_http_lms_list_node_t *
ngx_http_lms_list_lookup(ngx_http_request_t *r, ngx_http_lms_ctx_t *ctx)
{
    ngx_str_t                    key_cmp;
    ngx_http_lms_list_node_t    *node;

    key_cmp.data = r->uri.data;
    key_cmp.len = r->uri.len;
    node = ctx->cached_head;

    if (node == NULL) {
        return node;
    }

    while (node != NULL) {
        if (key_cmp.len != node->key_cmp.len) {
            node = node->next;
            continue;
        }

        if (ngx_strncasecmp(key_cmp.data, node->key_cmp.data, key_cmp.len) != 0) {
            node = node->next;
            continue;
        }

        break;
    }

    if (node != NULL)
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "@@@@@@@ Cache hits");

    return node;
}

static ngx_int_t
ngx_http_lms_get_source_path(const char *dir_path, ngx_str_t *file_name)
{
    DIR            *dir;
    struct dirent  *dp;
    ngx_int_t       found;
    ngx_int_t       rc;

    dir = opendir(dir_path);
    if (dir == NULL) {
        return NGX_ERROR;
    }

    found = 0;
    while ((dp = readdir(dir)) != NULL) {

        if (!ngx_strcmp(dp->d_name, ".")
            || !ngx_strcmp(dp->d_name, ".."))
        {
            continue;
        }

        if (dp->d_type != DT_REG) {
            continue;
        }

        if (fnmatch("*.mp4", dp->d_name, 0) == 0 ) {
            found = 1;
            break;
        }
    }

    rc = NGX_ERROR;
    if (found && NULL != file_name) {
        file_name->data = malloc(ngx_strlen(dir_path) + ngx_strlen(dp->d_name) + 1);
        if (file_name->data == NULL) {
            closedir(dir);
            return NGX_ERROR;
        }
        ngx_memcpy(file_name->data, dir_path, ngx_strlen(dir_path));
        ngx_memcpy(file_name->data + ngx_strlen(dir_path), dp->d_name, ngx_strlen(dp->d_name));
        file_name->len = ngx_strlen(dir_path) + ngx_strlen(dp->d_name);
        file_name->data[file_name->len] = '\0';

        rc = NGX_OK;
    }

    closedir(dir);
    return rc;
}

static ngx_str_t
ngx_http_lms_get_playlist(ngx_http_request_t *r)
{
    ngx_str_t           playlist;
    ngx_str_t           file_name;
    char                dir_path[1024];
    char                line_buffer[4096];
    AVFormatContext    *ifmtCtx = NULL;
    AVStream           *video_stream;
    ngx_int_t           i, j, k;
    int64_t             duration;
    ngx_int_t           segments_num, interval, seq;
    ngx_int_t           len;
    u_char             *pplaylist;

    interval = 5; // TODO:

    ngx_str_null(&playlist);

    // 定位uri中第二个斜杠的位置
    for (i = 1; i < (ngx_int_t) r->uri.len; i++) {
        if (r->uri.data[i] == '/') {
            break;
        }
    }

    // 定位uri倒数第一个斜杠的位置
    for (j = (ngx_int_t) (r->uri.len - 1); j >= 0; j--) {
        if (r->uri.data[j] == '/') {
            break;
        }
    }

    k = 0;
    while (i <= j) {
        dir_path[k++] = r->uri.data[i];
        i++;
    }
    dir_path[k] = '\0';

    ngx_str_null(&file_name);
    if (ngx_http_lms_get_source_path(dir_path, &file_name) != NGX_OK) {
        return playlist;
    }

    if (avformat_open_input(&ifmtCtx, (const char *) file_name.data, 0, 0) < 0) {
        goto release;
    }

    if (avformat_find_stream_info(ifmtCtx, 0) < 0) {
        goto release;
    }

    video_stream = NULL;
    for (i = 0; i < ifmtCtx->nb_streams; i++) {
        if (ifmtCtx->streams[i]->codec->codec_type == AVMEDIA_TYPE_VIDEO) {
            video_stream = ifmtCtx->streams[i];
            break;
        }
    }

    duration = (video_stream->duration * video_stream->time_base.num) / video_stream->time_base.den;
    segments_num = duration / interval;
    segments_num += ((duration % interval) ? 1 : 0);

    // estimate the total len
    len = 0;
    for (i = NGX_HTTP_LMS_START; i < NGX_HTTP_LMS_END; i++) {
        switch (i) {
            case NGX_HTTP_LMS_HEAD_CONST:
            case NGX_HTTP_LMS_HEAD_VERSION:
            case NGX_HTTP_LMS_HEAD_DURATION:
            case NGX_HTTP_LMS_ENDLIST:
                len += ngx_strlen(ngx_http_lms_playlist_item[i].fmt_str);
                break;
            case NGX_HTTP_LMS_FRAGMENT_LIST:
                // 4 means that extend 4 bytes for each fragment item
                len += ((ngx_strlen(ngx_http_lms_playlist_item[i].fmt_str) + 4) * segments_num);
                break;
            default:
                break;
        }
    }

    playlist.data = ngx_palloc(r->pool, len);
    if (playlist.data == NULL) {
        goto release;
    }

    pplaylist = playlist.data;
    len = 0;
    for (i = NGX_HTTP_LMS_START; i < NGX_HTTP_LMS_END; i++) {
        switch (i) {
            case NGX_HTTP_LMS_HEAD_CONST:
                ngx_memcpy(pplaylist, ngx_http_lms_playlist_item[i].fmt_str,
                                            ngx_strlen(ngx_http_lms_playlist_item[i].fmt_str));
                pplaylist += ngx_strlen(ngx_http_lms_playlist_item[i].fmt_str);
                len += ngx_strlen(ngx_http_lms_playlist_item[i].fmt_str);
                break;

            case NGX_HTTP_LMS_HEAD_VERSION:
            case NGX_HTTP_LMS_HEAD_DURATION:

                ngx_memset(line_buffer, 0, 4096);

                if (i == NGX_HTTP_LMS_HEAD_VERSION) {
                    ngx_snprintf((u_char *) line_buffer, 4096, ngx_http_lms_playlist_item[i].fmt_str, 3);
                } else {
                    ngx_snprintf((u_char *)line_buffer, 4096, ngx_http_lms_playlist_item[i].fmt_str, interval);
                }

                ngx_memcpy(pplaylist, line_buffer, ngx_strlen(line_buffer));
                pplaylist += ngx_strlen(line_buffer);
                len += ngx_strlen(line_buffer);
                break;

            default:
                break;
        }
    }

    for (seq = 0; seq < segments_num; seq++) {

        ngx_memset(line_buffer, 0, 4096);

        if (seq == (segments_num - 1)) {
            ngx_snprintf((u_char *)line_buffer, 4096,
                ngx_http_lms_playlist_item[NGX_HTTP_LMS_FRAGMENT_LIST].fmt_str,
                (float) (duration - (segments_num - 1) * interval), seq);
        } else {
            ngx_snprintf((u_char *)line_buffer, 4096,
                ngx_http_lms_playlist_item[NGX_HTTP_LMS_FRAGMENT_LIST].fmt_str, (float) interval, seq);
        }
        ngx_memcpy(pplaylist, line_buffer, ngx_strlen(line_buffer));
        pplaylist += ngx_strlen(line_buffer);
        len += ngx_strlen(line_buffer);
    }

    ngx_memcpy(pplaylist, ngx_http_lms_playlist_item[NGX_HTTP_LMS_ENDLIST].fmt_str,
                           ngx_strlen(ngx_http_lms_playlist_item[NGX_HTTP_LMS_ENDLIST].fmt_str));
    len += ngx_strlen(ngx_http_lms_playlist_item[NGX_HTTP_LMS_ENDLIST].fmt_str);

    playlist.len = len;

release:
    ngx_free(file_name.data);

    return playlist;
}

static ngx_http_lms_list_node_t *
ngx_http_lms_create_playlist(ngx_http_request_t *r, ngx_http_lms_ctx_t *ctx)
{
    ngx_http_lms_list_node_t    *node;
    ngx_slab_pool_t             *shpool;
    ngx_str_t                    playlist;

    /*
    *   TODO: 首先遍历链表，看是否存在已经达到老化时间的节点，如果有，则使用该节点
    *   找不到的情况下，才创建一个新的节点
    */

    shpool = ctx->shpool;
    node = ngx_slab_alloc_locked(shpool, sizeof(ngx_http_lms_list_node_t));
    if (node == NULL) {
        return NULL;
    }

    node->key_cmp.data = ngx_slab_alloc_locked(shpool, r->uri.len);
    if (node->key_cmp.data == NULL) {
        ngx_slab_free_locked(shpool, node);
        return NULL;
    }
    node->key_cmp.len = r->uri.len;
    ngx_memcpy(node->key_cmp.data, r->uri.data, r->uri.len);

    playlist = ngx_http_lms_get_playlist(r);
    if (playlist.data == NULL || playlist.len == 0) {
        ngx_slab_free_locked(shpool, node->key_cmp.data);
        ngx_slab_free_locked(shpool, node);
        return NULL;
    }

    node->playlist.data = ngx_slab_alloc_locked(shpool, playlist.len);
    if (node->playlist.data == NULL) {
        ngx_slab_free_locked(shpool, node->key_cmp.data);
        ngx_slab_free_locked(shpool, node);
        return NULL;
    }
    node->playlist.len = playlist.len;

    ngx_memcpy(node->playlist.data, playlist.data, playlist.len);

    return node;
}

static ngx_int_t
ngx_http_lms_list_insert(ngx_http_request_t *r, ngx_http_lms_ctx_t *ctx, ngx_http_lms_list_node_t *node)
{
    ngx_http_lms_list_node_t    *nodeptr;

    nodeptr = ctx->cached_head;
    if (nodeptr == NULL) {
        ctx->cached_head = node;
        ctx->shpool->data = ctx->cached_head;
        return NGX_OK;
    }

    while (nodeptr->next != NULL) {
        nodeptr = nodeptr->next;
    }

    nodeptr->next = node;

    return NGX_OK;
}

/* init_process */
static ngx_int_t
ngx_http_lms_init_worker(ngx_cycle_t *cycle)
{
	av_register_all();

    return NGX_OK;
}

static char *
ngx_http_lms(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_lms_handler;

	return NGX_CONF_OK;
}

static void *
ngx_http_lms_create_loc_conf(ngx_conf_t* cf)
{
    ngx_http_lms_loc_conf_t* conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_lms_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->shm_zone = NULL;

    return conf;
}

static char *
ngx_http_lms_merge_loc_conf(ngx_conf_t* cf, void* parent, void* child)
{
    ngx_http_lms_loc_conf_t* prev = parent;
    ngx_http_lms_loc_conf_t* conf = child;

    ngx_conf_merge_ptr_value(conf->shm_zone, prev->shm_zone, NULL);

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_lms_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_http_lms_ctx_t  *octx = data;

    size_t                      len;
    ngx_http_lms_ctx_t         *ctx;

    ctx = shm_zone->data;

    if (octx) {
        ctx->cached_head = octx->cached_head;
        ctx->shpool = octx->shpool;
        return NGX_OK;
    }

    ctx->shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        ctx->cached_head = ctx->shpool->data;
        return NGX_OK;
    }

    ctx->cached_head = NULL;
    ctx->shpool->data = ctx->cached_head;

    len = sizeof(" in lms_cached_zone \"\"") + shm_zone->shm.name.len;

    ctx->shpool->log_ctx = ngx_slab_alloc(ctx->shpool, len);
    if (ctx->shpool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(ctx->shpool->log_ctx, " in lms_cached_zone \"%V\"%Z",
                &shm_zone->shm.name);

    return NGX_OK;
}

static char *
ngx_http_lms_cached_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    u_char                     *p;
    ssize_t                     size;
    ngx_str_t                  *value, name, s;
    ngx_uint_t                  i;
    ngx_shm_zone_t             *shm_zone;
    ngx_http_lms_ctx_t         *ctx;

    ngx_http_lms_loc_conf_t    *llcf = ngx_http_conf_get_module_loc_conf(cf,
                                                            ngx_http_lms_module);

    value = cf->args->elts;

    ctx = NULL;
    size = 0;
    name.len = 0;

    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "zone=", 5) == 0) {

            name.data = value[i].data + 5;

            p = (u_char *) ngx_strchr(name.data, ':');

            if (p == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                "invalid zone size \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            name.len = p - name.data;

            s.data = p + 1;
            s.len = value[i].data + value[i].len - s.data;

            size = ngx_parse_size(&s);

            if (size == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                "invalid zone size \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            if (size < (ssize_t) (8 * ngx_pagesize)) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                "zone \"%V\" is too small", &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                        "\"%V\" must have \"zone\" parameter",
                        &cmd->name);
        return NGX_CONF_ERROR;
    }

    if (name.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                        "\"%V\" must have \"zone\" parameter",
                        &cmd->name);
        return NGX_CONF_ERROR;
    }

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_lms_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    ctx->cached_head = NULL;

    shm_zone = ngx_shared_memory_add(cf, &name, size,
                                 &ngx_http_lms_module);
    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    if (shm_zone->data) {
        ctx = shm_zone->data;

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "%V \"%V\" is already bounded",
                       &cmd->name, &name);
        return NGX_CONF_ERROR;
    }

    shm_zone->init = ngx_http_lms_init_zone;
    shm_zone->data = ctx;

    llcf->shm_zone = shm_zone;
    return NGX_CONF_OK;
}
