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


typedef struct ngx_http_arg_from_response_module_main_conf_s {
    ngx_flag_t  arg_from_resp;
    ngx_array_t *arg_name_uri;
} ngx_http_arg_from_response_module_main_conf_t;


/* 请求上下文 */
typedef struct arg_resp_request_ctx_s {
    ngx_array_t   *arg_val;
} arg_resp_request_ctx_t;

static void *arg_resp_main_conf_create(ngx_conf_t *cf);
static char *arg_resp_main_conf_init(ngx_conf_t *cf, void *conf);


/* 子请求结束时的处理方式 */
static ngx_int_t arg_resp_subrequest_post_handler(ngx_http_request_t *r, 
        void *data, ngx_int_t rc);

static ngx_int_t arg_resp_handler(ngx_http_request_t *r);

/* 用于获取变量 */
static ngx_int_t arg_resp_get_var(ngx_http_request_t *r, 
        ngx_http_variable_value_t *v, uintptr_t data);

static ngx_int_t arg_resp_postconfig(ngx_conf_t *cf);


static ngx_command_t arg_resp_commands[] = {
    {
        ngx_string("arg-from-resp"),                /* name, 配置参数名 */
        NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,        /* type, 参数类型 */
        ngx_conf_set_flag_slot,                     /* set, 参数处理函数 */
        NGX_HTTP_MAIN_CONF_OFFSET,                  /* conf, 配置所在位置 */
        offsetof(ngx_http_arg_from_response_module_main_conf_t, 
                 arg_from_resp),                    /* offset, 和内置set函数配合使用 */
        NULL,                                       /* post, 指向在set函数中需要用的数据 */
    },
    {
        ngx_string("arg-name-uri"),                 /* name, 配置参数名 */
        NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE2,        /* type, 参数类型 */
        ngx_conf_set_keyval_slot,                   /* set, 参数处理函数 */
        NGX_HTTP_MAIN_CONF_OFFSET,                  /* conf, 配置所在位置 */
        offsetof(ngx_http_arg_from_response_module_main_conf_t, 
                 arg_name_uri),                     /* offset, 和内置set函数配合使用 */
        NULL,                                       /* post, 指向在set函数中需要用的数据 */
    },
    ngx_null_command,
};

static ngx_http_module_t arg_resp_ctx = {
    NULL,
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
    amcf->arg_name_uri = NGX_CONF_UNSET_PTR;
    return amcf;
}

/*
 * 这个函数是在读取完配置文件(nginx.conf),从其中那带配置项之后再执行的
 * 所有可以用这个函数设置一下默认值
 */
static char *
arg_resp_main_conf_init(ngx_conf_t *cf, void *conf)
{
    ngx_http_arg_from_response_module_main_conf_t   *amcf = conf;
    if(amcf->arg_from_resp == NGX_CONF_UNSET) {
        amcf->arg_from_resp = 0;
    }
    if(amcf->arg_name_uri == NGX_CONF_UNSET_PTR) {
        amcf->arg_name_uri = NULL;
    }

    return NGX_CONF_OK;
}

static ngx_int_t 
arg_resp_postconfig(ngx_conf_t *cf)
{
    ngx_http_handler_pt                             *h;
    ngx_http_core_main_conf_t                       *cmcf;
    ngx_http_arg_from_response_module_main_conf_t   *amcf;
    ngx_keyval_t                                    *kv;
    ngx_uint_t                                      i;
    ngx_http_variable_t                             *v;

    /* 注入模块处理方法 */
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_POST_READ_PHASE].handlers);
    if(h == NULL) {
        return NGX_ERROR;
    }
    *h = arg_resp_handler;
    /* 添加变量 */
    amcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_arg_from_response_module);
    if(amcf->arg_from_resp && amcf->arg_name_uri) {
        kv = (ngx_keyval_t *) amcf->arg_name_uri->elts;
        for(i = 0; i < amcf->arg_name_uri->nelts; i++) {
            v = ngx_http_add_variable(cf, &kv[i].key, NGX_HTTP_VAR_INDEXED);
            if(v == NULL) {
                return NGX_ERROR;
            }
            v->get_handler = arg_resp_get_var;
            /* 用于存储数据的索引 */
            v->data = (uintptr_t)i;  /* data 对应arg_resp_get_var 中的 data 参数 */
        }
    }
    /* ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "arg_resp_postconfig --------------------> done"); */
    return NGX_OK;
}


/* 用于获取变量 */
static ngx_int_t 
arg_resp_get_var(ngx_http_request_t *r, ngx_http_variable_value_t *v, 
        uintptr_t data)
{
    arg_resp_request_ctx_t  *rctx;
    ngx_str_t               *sv, val;
    ngx_uint_t              idx;

    rctx = ngx_http_get_module_ctx(r, ngx_http_arg_from_response_module);
     
    if(rctx == NULL || rctx->arg_val == NULL) {
        return NGX_ERROR;
    }


    idx = (ngx_uint_t)data;
    sv = rctx->arg_val->elts;
    val = sv[idx];
    
    /* ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "arg_resp_get_var --------------------> rctx = %p, idx = %i, val = %V", rctx, idx, &val); */

    if(val.len > 0) {
        *v = ngx_http_variable_true_value;
        v->len = val.len;
        v->data = val.data;
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
    ngx_http_request_t                              *pr;
    arg_resp_request_ctx_t                          *rctx;
    off_t                                           left, len, pos;
    ngx_chain_t                                     *c;
    ngx_uint_t                                      idx;
    ngx_str_t                                       *v, *val;
    /* ngx_keyval_t                                    *kv, keyval; */
    ngx_http_arg_from_response_module_main_conf_t   *amcf;


    pr = r->parent;
    /* 请求上下问要在父请求中拿 */
    rctx = ngx_http_get_module_ctx(pr, ngx_http_arg_from_response_module);
    amcf = ngx_http_get_module_main_conf(pr, ngx_http_arg_from_response_module);

    if(rctx == NULL || rctx->arg_val->nelts == amcf->arg_name_uri->nelts) {
        /* TODO
         * 搞清楚为啥会有这个请求
         */
        ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "arg_resp_subrequest_post_handler --------------> running again in rctx = %p(maybe NULL)");
        return NGX_DECLINED;
    }

    idx = (ngx_uint_t )data;
    /* kv = amcf->arg_name_uri->elts; */
    /* keyval = kv[idx]; */
    v = rctx->arg_val->elts;
    val = v + idx;

    /* printf("arg_resp_subrequest_post_handler --------------> rctx=%p, rctx->arg_val->nelts=%lu, amcf->arg_name_uri->nelts=%lu, v=%p, val=%p.\n",  */
    /*        rctx, rctx->arg_val->nelts, amcf->arg_name_uri->nelts, (void *)v, (void *)val); */

    val->len = 0;
    if(r->headers_out.status == NGX_HTTP_OK) {
        val->len = r->headers_out.content_length_n;
        if( (val->data = ngx_pcalloc(pr->pool, val->len + 1)) == NULL ) {
            ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "alloc memory "
                    "for val.data error.");
            return NGX_ERROR;
        } 
        val->data[val->len] = 0;
        left = val->len;
        for(c = r->out, pos = 0; left && c; c = c->next) {
            len = c->buf->last - c->buf->pos;
            if(len > left) {
                memcpy(val->data + pos, c->buf->pos, left);
                break;
            } else {
                memcpy(val->data + pos, c->buf->pos, len);
                pos += len;
                left -= len;
            }
        }
    }

    rctx->arg_val->nelts++;

    ngx_chain_update_sent(r->out, r->headers_out.content_length_n);
/* done: */
    /* printf("arg_resp_subrequest_post_handler -----> idx = %lu, arg = %s, val = %s, val.len=%lu\n", idx, keyval.key.data, val->data, val->len); */
    /* 设置主请求的写回调函数,重新走HTTP的流程 */
    /* 打印请求数 */
    if(rctx->arg_val->nelts == amcf->arg_name_uri->nelts) {
        /* printf("arg_resp_subrequest_post_handler: ******************* goto other phases. **************************\n"); */
        pr->write_event_handler = ngx_http_core_run_phases;
    } else  {
        /* printf("arg_resp_subrequest_post_handler: ################### stay in this phases. ************************\n"); */
        pr->write_event_handler = ngx_http_request_empty_handler;
    }
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
    ngx_uint_t                                      i;
    ngx_keyval_t                                    *kv;

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
        /* printf("in arg_resp_handler SECOND time ----> r=%p, rctx=%p, r->postponed=%p, r->sr=%i.\n", r, rctx, r->postponed, r->subrequests); */
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "the second time in to the handler");
        
        return NGX_DECLINED;
    }
    rctx = _ngx_pcalloc_pool(r->pool, arg_resp_request_ctx_t, NGX_ERROR);
    rctx->arg_val = _ngx_pcalloc_pool(r->pool, ngx_array_t, NGX_ERROR);
    rctx->arg_val->pool = r->pool;
    rctx->arg_val->size = sizeof(ngx_str_t);
    rctx->arg_val->nelts = 0;
    rctx->arg_val->nalloc = amcf->arg_name_uri->nelts;
    rctx->arg_val->elts = ngx_pcalloc(r->pool, sizeof(ngx_str_t) * rctx->arg_val->nalloc);
    if(rctx->arg_val->elts == NULL) {
        return NGX_ERROR;
    }
    ngx_http_set_ctx(r, rctx, ngx_http_arg_from_response_module);

    /* r->write_event_handler = ngx_http_request_empty_handler; */

    kv = amcf->arg_name_uri->elts;
    for (i = 0; i < amcf->arg_name_uri->nelts; i++) {
        psr = _ngx_pcalloc_pool(r->pool, ngx_http_post_subrequest_t, 
                NGX_HTTP_INTERNAL_SERVER_ERROR);
        psr->handler = arg_resp_subrequest_post_handler;
        psr->data = (void *)i;

        rc = ngx_http_subrequest(r, &kv[i].value, NULL, &sr, psr, 
                NGX_HTTP_SUBREQUEST_IN_MEMORY);
        if(rc != NGX_OK) {
            return NGX_ERROR;
        }
        /* printf("in arg_resp_handler after create sub request -----> rcnt=%u, rcnt=%u, idx=%lu, r=%p, sr=%p\n", r->main->count, sr->main->count, i, r, sr); */
    }

    return NGX_DONE;
}
