package burp;


import java.io.PrintWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static burp.IScannerInsertionPoint.INS_PARAM_BODY;
import static burp.IScannerInsertionPoint.INS_PARAM_URL;

public class BurpExtender implements IBurpExtender, IScannerCheck
{
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    public static PrintWriter stdout;

    //payload
    private static final byte[] PAYLOAD = "1415926'\"<xxx'\"xxx>xxx".getBytes();
    //用于hook函数，判断是否是第一次请求，避免将后面的js页面也添加<script></script>导致报错。
    public static boolean first_flag = true;

    //
    // implement IBurpExtender
    //

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
    {
        // keep a reference to our callbacks object
        this.callbacks = callbacks;

        //设置输出
        stdout = new PrintWriter(callbacks.getStdout(), true);

        // obtain an extension helpers object
        helpers = callbacks.getHelpers();

        // set our extension name
        callbacks.setExtensionName("XssScanner");

        // 输出作者信息
        stdout.println("Author:lufei");

        // register ourselves as a custom scanner check
        callbacks.registerScannerCheck(this);
    }

    // helper method to search a response for occurrences of a literal match string
    // and return a list of start/end offsets
    private List<int[]> getMatches(byte[] response, byte[] match)
    {
        List<int[]> matches = new ArrayList<int[]>();

        int start = 0;
        while (start < response.length)
        {
            start = helpers.indexOf(response, match, true, start, response.length);
            if (start == -1)
                break;
            matches.add(new int[] { start, start + match.length });
            start += match.length;
        }

        return matches;
    }

    //
    // implement IScannerCheck
    //


    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        return null;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint)
    {

        boolean match_flag;
        Pattern pattern;
        Matcher matcher;
        //定义xss检查对象
        XssChecker xssChecker;
        //定义返回headers和body
        String response = "";

        //设置为第一次请求，能够对非js页面添加hook函数
        first_flag = true;

        //判断payload插入的类型
        byte type = insertionPoint.getInsertionPointType();

        //xss只检测url参数和body参数
        if(type != INS_PARAM_URL && type != INS_PARAM_BODY)
            return null;

        //构造payLoad数据包
        byte[] checkRequest = insertionPoint.buildRequest(PAYLOAD);


        //从构造好的checkRequest中，获取完整的URL，并且checkRequestResponse设置URL
        pattern = Pattern.compile("/.*?(?=HTTP)");
        matcher = pattern.matcher(new String(checkRequest));
        matcher.find();
        String path = matcher.group(0);
        //从raw包中获取path地址
        String poc_url = baseRequestResponse.getHttpService().getProtocol()+"://"+baseRequestResponse.getHttpService().getHost()+":"+baseRequestResponse.getHttpService().getPort()+path;

        //判断是否是post还是get,发送不同的请求
        if( type == INS_PARAM_BODY )
        {
            //stdout.println(new String(checkRequest));
            pattern = Pattern.compile("^\\s+(.*)",Pattern.MULTILINE);
            matcher = pattern.matcher(new String(checkRequest));
            matcher.find();
            String body = matcher.group(1);
            xssChecker = new XssChecker(poc_url,helpers.analyzeRequest(baseRequestResponse.getRequest()).getHeaders(),body,"POST");
        }else {
            xssChecker = new XssChecker(poc_url,helpers.analyzeRequest(baseRequestResponse.getRequest()).getHeaders(),"","GET");
        }



        //使用htmlunit发送请求
        xssChecker.send_request();

        //由于使用htmlunit，而不适用burp的api发送，为了不改变burp的习惯，这里先清空，然后使用htmlunit后的结果进行填充
        IHttpRequestResponse checkRequestResponse = new IHttpRequestResponse() {
            byte[] request;
            byte[] response;
            String url;
            IHttpService service;

            @Override
            public byte[] getRequest() {
                return this.request;
            }

            @Override
            public void setRequest(byte[] request) {
                this.request = request;
            }

            @Override
            public byte[] getResponse() {
                return this.response;
            }

            @Override
            public void setResponse(byte[] response) {
                this.response = response;
            }

            @Override
            public String getComment() {
                return this.url;
            }

            @Override
            public void setComment(String comment) {
                this.url = comment;
            }


            @Override
            public String getHighlight() {
                return null;
            }

            @Override
            public void setHighlight(String color) {

            }

            @Override
            public IHttpService getHttpService() {
                return service;
            }

            @Override
            public void setHttpService(IHttpService httpService) {
                service = httpService;
            }

        };

        //设置发送包
        checkRequestResponse.setRequest(checkRequest);
        //设置http服务
        checkRequestResponse.setHttpService(baseRequestResponse.getHttpService());

        //构造返回包
        for (String tmp:helpers.analyzeResponse(baseRequestResponse.getResponse()).getHeaders()
        ) {
            response = response + tmp + "\n";
        }
        //response包含了headers和body
        response = response + "\n" + xssChecker.response_body;
        checkRequestResponse.setResponse(response.getBytes());


        //对返回的数据包进行匹配结果
        ArrayList<String> result_list = xssChecker.check_js_html_xss();
        if(result_list.isEmpty()){ return null; }


        // look for matches of our active check grep string
        List<int[]> matches = getMatches(checkRequestResponse.getResponse(), result_list.get(1).getBytes());
        if (matches.size() > 0)
        {
            // get the offsets of the payload within the request, for in-UI highlighting
            List<int[]> requestHighlights = new ArrayList<>(1);
            requestHighlights.add(insertionPoint.getPayloadOffsets(result_list.get(1).getBytes()));

            // report the issue
            List<IScanIssue> issues = new ArrayList<>(1);
            issues.add(new CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    helpers.analyzeRequest(baseRequestResponse).getUrl(),
                    new IHttpRequestResponse[] { callbacks.applyMarkers(checkRequestResponse, requestHighlights, matches) },
                    "Cross Site Scripting",
                    "" + result_list.get(0),
                    "High"));
            return issues;
        }
        else return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue)
    {
        // This method is called when multiple issues are reported for the same URL
        // path by the same extension-provided check. The value we return from this
        // method determines how/whether Burp consolidates the multiple issues
        // to prevent duplication
        //
        // Since the issue name is sufficient to identify our issues as different,
        // if both issues have the same name, only report the existing issue
        // otherwise report both issues
        if (existingIssue.getIssueName().equals(newIssue.getIssueName()))
            return -1;
        else return 0;
    }
}

//
// class implementing IScanIssue to hold our custom scan issue details
//
class CustomScanIssue implements IScanIssue
{
    private IHttpService httpService;
    private URL url;
    private IHttpRequestResponse[] httpMessages;
    private String name;
    private String detail;
    private String severity;

    public CustomScanIssue(
            IHttpService httpService,
            URL url,
            IHttpRequestResponse[] httpMessages,
            String name,
            String detail,
            String severity)
    {
        this.httpService = httpService;
        this.url = url;
        this.httpMessages = httpMessages;
        this.name = name;
        this.detail = detail;
        this.severity = severity;
    }

    @Override
    public URL getUrl()
    {
        return url;
    }

    @Override
    public String getIssueName()
    {
        return name;
    }

    @Override
    public int getIssueType()
    {
        return 0;
    }

    @Override
    public String getSeverity()
    {
        return severity;
    }

    @Override
    public String getConfidence()
    {
        return "Certain";
    }

    @Override
    public String getIssueBackground()
    {
        return null;
    }

    @Override
    public String getRemediationBackground()
    {
        return null;
    }

    @Override
    public String getIssueDetail()
    {
        return detail;
    }

    @Override
    public String getRemediationDetail()
    {
        return null;
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages()
    {
        return httpMessages;
    }

    @Override
    public IHttpService getHttpService()
    {
        return httpService;
    }

}