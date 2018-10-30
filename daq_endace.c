/*
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <daq_api.h>
#include <sfbpf_dlt.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dagapi.h>
#include <pcap.h>
#include <arpa/inet.h>

#define DAQ_ENDACE_VERSION 1
#define ERROR_BUF_SIZE	128

typedef struct _endace_dag_context {
	int stream;
	int fd;

	int breakloop;
	int snaplen;

	char name[DAGNAME_BUFSIZE];
	char errbuf[ERROR_BUF_SIZE];

	struct timeval timeout;
	struct timeval poll;

	uint8_t *bottom;

	DAQ_Analysis_Func_t analysis_func;
	DAQ_Stats_t stats;
	DAQ_State state;

} EndaceDAGCtx_t;

static int endace_daq_initialize(const DAQ_Config_t * config, void **ctxt_ptr, char *errbuf, size_t len)
{
	// Passive mode is all that is currently supported
	if (config->mode != DAQ_MODE_PASSIVE)
	{
		snprintf(errbuf, len, "%s: Unsupported mode", __FUNCTION__);
		return DAQ_ERROR;
	}

	// Setup the context
	EndaceDAGCtx_t *ctx = calloc(1, sizeof(EndaceDAGCtx_t));
	if (!ctx)
	{
		snprintf(errbuf, len, "%s: failed to allocate memory for the new Endace DAG context!", __FUNCTION__);
		return DAQ_ERROR_NOMEM;
	}

	// Parse device information out for processing
	if ( dag_parse_name(config->name, ctx->name, DAGNAME_BUFSIZE, &ctx->stream) < 0 )
	{
		snprintf(errbuf, len, "%s: invalid device specification!", __FUNCTION__);
		return DAQ_ERROR;
	}

	ctx->state = DAQ_STATE_INITIALIZED;
	ctx->snaplen = config->snaplen;

	*ctxt_ptr = ctx;
	return DAQ_SUCCESS;
}

static int endace_daq_set_filter(void *handle, const char *filter)
{
    return DAQ_SUCCESS;
}

static int endace_daq_start(void *handle)
{

	EndaceDAGCtx_t *ctx = (EndaceDAGCtx_t *) handle;
	if (!ctx)
	{
		return DAQ_ERROR;
	}

	if ((ctx->fd = dag_open(ctx->name)) < 0)
	{
		snprintf(ctx->errbuf, ERROR_BUF_SIZE, "%s: failed opening to Endace adapter %s!", __FUNCTION__, ctx->name);
		return DAQ_ERROR;
	}

	if ((dag_attach_stream(ctx->fd, ctx->stream, 0, 0)) < 0)
	{
		snprintf(ctx->errbuf, ERROR_BUF_SIZE, "%s: failed attaching to Endace adapter:stream %s:%d!", __FUNCTION__, ctx->name, ctx->stream);
		return DAQ_ERROR;
	}

	if ((dag_start_stream(ctx->fd,ctx->stream)) < 0)
	{
		snprintf(ctx->errbuf, ERROR_BUF_SIZE, "%s: failed starting stream: %d on Endace adapter: %s!", __FUNCTION__, ctx->stream, ctx->name);
		return DAQ_ERROR;
	}

	ctx->timeout.tv_sec = 0;
	ctx->timeout.tv_usec = 100 * 1000; // 100ms wait time
	ctx->poll.tv_sec = 0;
	ctx->poll.tv_usec = 10 * 1000; // 10ms poll time

	dag_set_stream_poll(ctx->fd, ctx->stream, 32 * 1024, &(ctx->timeout), &(ctx->poll));

	ctx->state = DAQ_STATE_STARTED;
	return DAQ_SUCCESS;
}

#if DAQ_API_VERSION == 0x00010001
static int endace_daq_acquire(void *handle, int cnt, DAQ_Analysis_Func_t callback, void *user)
{
#elif DAQ_API_VERSION >= 0x00010002
static int endace_daq_acquire(void *handle, int cnt, DAQ_Analysis_Func_t callback, DAQ_Meta_Func_t metaback, void *user)
{
#endif
	int packets = 0;

	DAQ_PktHdr_t hdr;
	DAQ_Verdict verdict;

	uint8_t *frame = NULL;
	uint8_t *ep = NULL;

	uint64_t lts;

	dag_record_t *rec;
	size_t reclen;

	EndaceDAGCtx_t *ctx = (EndaceDAGCtx_t *) handle;
	if (!ctx)
	{
		return DAQ_ERROR;
	}
	ctx->analysis_func = callback;

	while (!ctx->breakloop && (packets < cnt || cnt <=0))
	{
		if ((ep = dag_advance_stream(ctx->fd, ctx->stream, &ctx->bottom)) == NULL)
		{
			snprintf(ctx->errbuf, ERROR_BUF_SIZE, "%s: failed advancing stream: %d on Endace adapter: %s!", __FUNCTION__, ctx->stream, ctx->name);
			return DAQ_ERROR;
		}

		if (ep - ctx->bottom == 0)
                {
                    /* Timeout with no packets, break out so we can
                     * exit if needed. */
                    return 0;
                }

		while (ctx->bottom < ep && (packets < cnt || cnt <=0))
		{

			rec = (dag_record_t*)ctx->bottom;
			reclen = ntohs(rec->rlen);

			/*  Advance the stream if a short read is detected */
			if ((ep - ctx->bottom) < reclen) break;

			/* Advance the current pointer */
			ctx->bottom += reclen;

			if (rec->type != TYPE_ETH)
				continue;

			frame = &(rec->rec.eth.dst[0]);

			hdr.caplen = (((uint8_t *)rec + reclen) - frame);
			hdr.pktlen = hdr.caplen;

			lts = rec->ts;
			hdr.ts.tv_sec = lts >> 32;
			lts = ((lts & 0xffffffffULL) * 1000 * 1000);
			lts += (lts & 0x80000000ULL) << 1;
			hdr.ts.tv_usec = lts >> 32;

			if(hdr.ts.tv_usec >= 1000000) {
				hdr.ts.tv_sec += 1;
				hdr.ts.tv_usec -= 1000000;
			}

#if DAQ_API_VERSION == 0x00010001
			hdr.device_index = -1;
#elif DAQ_API_VERSION >= 0x00010002
			hdr.ingress_index = -1;
			hdr.ingress_group = -1;
			hdr.egress_index = -1;
			hdr.egress_group = -1;
#endif
			hdr.flags = 0;

			ctx->stats.packets_received++;
			verdict = ctx->analysis_func(user, &hdr, frame);
			if (verdict >= MAX_DAQ_VERDICT)
			{
					verdict = DAQ_VERDICT_PASS;
			}
			ctx->stats.verdicts[verdict]++;
			packets++;

			if(rec->lctr)
				ctx->stats.hw_packets_dropped += rec->lctr;
		}
	}
	return DAQ_SUCCESS;
}

static int endace_daq_inject(void *handle, const DAQ_PktHdr_t * hdr, const uint8_t * packet_data,
                              uint32_t len, int reverse)
{
    return DAQ_SUCCESS;
}

static int endace_daq_breakloop(void *handle)
{
	EndaceDAGCtx_t *ctx = (EndaceDAGCtx_t *) handle;
	if (!ctx)
	{
		return DAQ_ERROR;
	}
	ctx->breakloop = 1;
	return DAQ_SUCCESS;
}

static int endace_daq_stop(void *handle)
{
	EndaceDAGCtx_t *ctx = (EndaceDAGCtx_t *) handle;
	if (!ctx)
	{
		return DAQ_ERROR;
	}
	dag_stop_stream(ctx->fd, ctx->stream);
	dag_detach_stream(ctx->fd, ctx->stream);
 	ctx->state = DAQ_STATE_STOPPED;
	return DAQ_SUCCESS;
}

static void endace_daq_shutdown(void *handle)
{
	EndaceDAGCtx_t *ctx = (EndaceDAGCtx_t *) handle;
	if (!ctx)
	{
		return;
	}
	dag_close(ctx->fd);
	free(ctx);
}

static DAQ_State endace_daq_check_status(void *handle)
{
	EndaceDAGCtx_t *ctx = (EndaceDAGCtx_t *) handle;
	if (!ctx)
	{
		return DAQ_STATE_UNINITIALIZED;
	}
	return ctx->state;
}

static int endace_daq_get_stats(void *handle, DAQ_Stats_t * stats)
{
	EndaceDAGCtx_t *ctx = (EndaceDAGCtx_t *) handle;
	if (!ctx)
	{
		return DAQ_ERROR;
	}
	ctx->stats.hw_packets_received = (ctx->stats.packets_received + ctx->stats.hw_packets_dropped);
	memcpy(stats, &(ctx->stats), sizeof(DAQ_Stats_t));
	return DAQ_SUCCESS;
}

static void endace_daq_reset_stats(void *handle)
{
	EndaceDAGCtx_t *ctx = (EndaceDAGCtx_t *) handle;
	if (!ctx)
	{
		return;
	}
	memset(&(ctx->stats), 0, sizeof(DAQ_Stats_t));
}

static int endace_daq_get_snaplen(void *handle)
{
	EndaceDAGCtx_t *ctx = (EndaceDAGCtx_t *) handle;
	if (!ctx)
	{
		return 0;
	}
	return ctx->snaplen;
}

static uint32_t endace_daq_get_capabilities(void *handle)
{
    return DAQ_CAPA_NONE;
}

static int endace_daq_get_datalink_type(void *handle)
{
    return DLT_EN10MB;
}

static const char *endace_daq_get_errbuf(void *handle)
{
	EndaceDAGCtx_t *ctx = (EndaceDAGCtx_t *) handle;
	if (!ctx)
	{
		return NULL;
	}
	return ctx->errbuf;
}

static void endace_daq_set_errbuf(void *handle, const char *string)
{
	EndaceDAGCtx_t *ctx = (EndaceDAGCtx_t *) handle;
	if (!ctx)
	{
		return;
	}
	if (!string)
	{
		return;
	}
	DPE(ctx->errbuf, "%s", string);
}

static int endace_daq_get_device_index(void *handle, const char *device)
{
    return DAQ_ERROR_NOTSUP;
}

#ifdef BUILDING_SO
DAQ_SO_PUBLIC const DAQ_Module_t DAQ_MODULE_DATA =
#else
  const DAQ_Module_t endace_daq_module_data =
#endif
  {
    .api_version = DAQ_API_VERSION,
    .module_version = DAQ_ENDACE_VERSION,
    .name = "endace",
    .type = DAQ_TYPE_INTF_CAPABLE | DAQ_TYPE_NO_UNPRIV,
    .initialize = endace_daq_initialize,
    .set_filter = endace_daq_set_filter,
    .start = endace_daq_start,
    .acquire = endace_daq_acquire,
    .inject = endace_daq_inject,
    .breakloop = endace_daq_breakloop,
    .stop = endace_daq_stop,
    .shutdown = endace_daq_shutdown,
    .check_status = endace_daq_check_status,
    .get_stats = endace_daq_get_stats,
    .reset_stats = endace_daq_reset_stats,
    .get_snaplen = endace_daq_get_snaplen,
    .get_capabilities = endace_daq_get_capabilities,
    .get_datalink_type = endace_daq_get_datalink_type,
    .get_errbuf = endace_daq_get_errbuf,
    .set_errbuf = endace_daq_set_errbuf,
    .get_device_index = endace_daq_get_device_index,
#if DAQ_API_VERSION >= 0x00010002
    .modify_flow = NULL,
    .hup_prep = NULL,
    .hup_apply = NULL,
    .hup_post = NULL,
#endif
  };
