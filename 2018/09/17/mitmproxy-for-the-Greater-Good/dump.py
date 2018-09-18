import mitmproxy
from mitmproxy import ctx
import uuid
import ntpath
from pprint import pformat


def printHeaders(description, headers):
    ppHeaders = pformat(headers.fields, width=120)
    headerLines = ppHeaders.split("\n,\n")
    ctx.log.info("%s\n%s" % (description, "\n".join(headerLines)))


class DumpAll:
    def response(self, flow: mitmproxy.http.HTTPFlow):
        printHeaders("Request headers", flow.request.headers)
        ctx.log.info("Request: {0}\n-q-\n{1}".format(flow.request.url,
                                                     flow.request.content))

        printHeaders('Response headers', flow.response.headers)
        ctx.log.info('Response: {2} {3} {0}\n-p-\n{1}'.format(flow.request.url,
                                                              flow.response.text,
                                                              flow.response.status_code,
                                                              flow.response.reason))


addons = [DumpAll()]
