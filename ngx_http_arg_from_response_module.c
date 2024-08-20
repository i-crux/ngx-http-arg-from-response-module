#include <ngx_http.h>

#define _ngx_str_t_casecmp(ngx_str1, ngx_str2) ({                           \
        ngx_int_t _rc = (ngx_str1)->len - (ngx_str2)->len;                  \
        _rc = _rc == 0 ? ngx_strncasecmp((ngx_str1)->data, (ngx_str2)->data,\
                (ngx_str1)->len) : _rc;                                     \
        _rc; })

#define _ngx_pcalloc_pool(pool, type, reterr) ({                \
            type *_ptr;                                         \
            if( !(_ptr = ngx_pcalloc((pool), sizeof(type))) ) { \
                return (reterr);                                \
            }                                                   \
            _ptr;                                               \
        })

#define _ARG_URI        "/_arg"
#define _ARG_NAME       "argresp"

typedef struct ngx_http_arg_from_response_module_main_conf_s {
    ngx_flag_t  arg_from_resp;
    ngx_str_t   arg_uri; 
    /* ngx_array_t arg_name_uri; */
} ngx_http_arg_from_response_module_main_conf_t;


/* 请求上下文 */
typedef struct arg_resp_request_ctx_s {
    ngx_str_t   arg_val;
} arg_resp_request_ctx_t;

static void *arg_resp_main_conf_create(ngx_conf_t *cf);
static char *arg_resp_main_conf_init(ngx_conf_t *cf, void *conf);

/* 子请求结束时的处理方式 */
static ngx_int_t arg_resp_subrequest_post_handler(ngx_http_request_t *r, 
        void *data, ngx_int_t rc);

static ngx_int_t arg_resp_handler(ngx_http_request_t *r);

/* 用于添加变量 */
static ngx_int_t arg_resp_preconfig(ngx_conf_t *cf);
/* 用于获取变量 */
static ngx_int_t arg_resp_get_var(ngx_http_request_t *r, 
        ngx_http_variable_value_t *v, uintptr_t data);

static ngx_int_t arg_resp_postconfig(ngx_conf_t *cf);

static ngx_str_t var_arg_resp = ngx_string(_ARG_NAME);

static ngx_command_t arg_resp_commands[] = {
    {
        ngx_string("arg-from-resp"),                /* name, 配置参数名 */
        NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,        /* type, 参数类型 */
        ngx_conf_set_flag_slot,                     /* set, 参数处理函数 */
        NGX_HTTP_MAIN_CONF_OFFSET,                   /* conf, 配置所在位置 */
        offsetof(ngx_http_arg_from_response_module_main_conf_t, 
                 arg_from_resp),                    /* offset, 和内置set函数配合使用 */
        NULL,                                       /* post, 指向在set函数中需要用的数据 */
    },
    {
        ngx_string("arg-uri"),                      /* name, 配置参数名 */
        NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,        /* type, 参数类型 */
        ngx_conf_set_str_slot,                      /* set, 参数处理函数 */
        NGX_HTTP_MAIN_CONF_OFFSET,                  /* conf, 配置所在位置 */
        offsetof(ngx_http_arg_from_response_module_main_conf_t, 
                 arg_uri),                             /* offset, 和内置set函数配合使用 */
        NULL,                                       /* post, 指向在set函数中需要用的数据 */
    },
    ngx_null_command,
};

static ngx_http_module_t arg_resp_ctx = {
    arg_resp_preconfig,
    arg_resp_postconfig,
    arg_resp_main_conf_create,
    arg_resp_main_conf_init,
    NULL,
    NULL,
    NULL,
    NULL,
};

ngx_module_t ngx_http_arg_from_response_module = {
    NGX_MODULE_V1,
    &arg_resp_ctx,
    arg_resp_commands,
    NGX_HTTP_MODULE,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NGX_MODULE_V1_PADDING,
};
    

static void *
arg_resp_main_conf_create(ngx_conf_t *cf)
{
    ngx_http_arg_from_response_module_main_conf_t   *amcf;

    amcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_arg_from_response_module_main_conf_t));
    if(amcf == NULL) {
        return NULL;
    }
    amcf->arg_from_resp = NGX_CONF_UNSET;
    ngx_str_null(&amcf->arg_uri);
    return amcf;
}

static char *
arg_resp_main_conf_init(ngx_conf_t *cf, void *conf)
{
    ngx_http_arg_from_response_module_main_conf_t   *amcf = conf;
    if(amcf->arg_from_resp == NGX_CONF_UNSET) {
        amcf->arg_from_resp = 0;
    }
    if(amcf->arg_uri.data == NULL) {
        ngx_str_set(&amcf->arg_uri, _ARG_URI);
    }

    return NGX_CONF_OK;
}

static ngx_int_t 
arg_resp_postconfig(ngx_conf_t *cf)
{
    ngx_http_handler_pt         *h;
    ngx_http_core_main_conf_t   *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_POST_READ_PHASE].handlers);
    if(h == NULL) {
        return NGX_ERROR;
    }
    *h = arg_resp_handler;
    return NGX_OK;
}

/* 用于添加变量 */
static ngx_int_t 
arg_resp_preconfig(ngx_conf_t *cf)
{
    ngx_http_variable_t     *v;

    v = ngx_http_add_variable(cf, &var_arg_resp, NGX_HTTP_VAR_INDEXED);
    if(v == NULL) {
        return NGX_ERROR;
    }
    v->get_handler = arg_resp_get_var;
    v->data = 0;
    return NGX_OK;
}

/* 用于获取变量 */
static ngx_int_t 
arg_resp_get_var(ngx_http_request_t *r, ngx_http_variable_value_t *v, 
        uintptr_t data)
{
    arg_resp_request_ctx_t *rctx;
    rctx = ngx_http_get_module_ctx(r, ngx_http_arg_from_response_module);
    if(rctx == NULL) {
        return NGX_ERROR;
    }
    
    if(rctx->arg_val.len > 0) {
        *v = ngx_http_variable_true_value;
        v->len = rctx->arg_val.len;
        v->data = rctx->arg_val.data;
    } else {
        *v = ngx_http_variable_null_value;
    }
    /* printf("get var:%sfuck\n", v->data); */
    return NGX_OK;
}

static ngx_int_t 
arg_resp_subrequest_post_handler(ngx_http_request_t *r, 
        void *data, ngx_int_t rc)
{
    ngx_http_request_t      *pr;
    arg_resp_request_ctx_t  *rctx;
    off_t                   left, len, pos;
    ngx_chain_t             *c;

    pr = r->parent;
    rctx = data;

    rctx->arg_val.len = 0;
    if(r->headers_out.status == NGX_HTTP_OK) {
        rctx->arg_val.len = r->headers_out.content_length_n;
        if( (rctx->arg_val.data = 
                    ngx_pcalloc(pr->pool, rctx->arg_val.len + 1)) == NULL ) {
            ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "alloc memory "
                    "for arg_val.data error.");
            return NGX_ERROR;
        } 
        rctx->arg_val.data[rctx->arg_val.len] = 0;
        left = rctx->arg_val.len;
        for(c = r->out, pos = 0; left && c; c = c->next) {
            len = c->buf->last - c->buf->pos;
            if(len > left) {
                memcpy(rctx->arg_val.data + pos, c->buf->pos, left);
                break;
            } else {
                memcpy(rctx->arg_val.data + pos, c->buf->pos, len);
                pos += len;
                left -= len;
            }
        }
    }

    ngx_chain_update_sent(r->out, r->headers_out.content_length_n);
    /* 设置主请求的写回调函数,重新走HTTP的流程 */
    pr->write_event_handler = ngx_http_core_run_phases;
    return NGX_OK;
}

static ngx_int_t 
arg_resp_handler(ngx_http_request_t *r)
{
    ngx_http_arg_from_response_module_main_conf_t   *amcf;
    arg_resp_request_ctx_t                          *rctx;
    ngx_http_post_subrequest_t                      *psr;
    ngx_http_request_t                              *sr;
    ngx_int_t                                       rc;

    amcf = ngx_http_get_module_main_conf(r, ngx_http_arg_from_response_module);
    if(amcf->arg_from_resp == 0) {
        return NGX_DECLINED;
    }

    rctx = ngx_http_get_module_ctx(r, ngx_http_arg_from_response_module);
    if(rctx != NULL) {
        /* 第二次进入此函数 */
        /* if(rctx->redis_val.len > 0) { */
        /*     printf("HANDLER redis val: fuck%sfuck\n", rctx->redis_val.data); */
        /* } */
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "the second time in to the handler");
        return NGX_DECLINED;
    }
    rctx = _ngx_pcalloc_pool(r->pool, arg_resp_request_ctx_t, NGX_ERROR);
    ngx_http_set_ctx(r, rctx, ngx_http_arg_from_response_module);

    psr = _ngx_pcalloc_pool(r->pool, ngx_http_post_subrequest_t, 
            NGX_HTTP_INTERNAL_SERVER_ERROR);
    psr->handler = arg_resp_subrequest_post_handler;
    psr->data = rctx;


    rc = ngx_http_subrequest(r, &amcf->arg_uri, NULL, &sr, psr, 
            NGX_HTTP_SUBREQUEST_IN_MEMORY);
    if(rc != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_DONE;
}
