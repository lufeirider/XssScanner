
<script type="text/javascript">
	var s=location.search;
	s=s.substring(1,s.length);

	var url="";
	if(s.indexOf("url=")>-1){
		var pos=s.indexOf("url=")+4;
		url=s.substring(pos,s.length); //<--得到地址栏里的url参数
	}else{
		url="javascript:void(0)";
	}
	location.href=url;
</script>

<script type="text/javascript" src="1.js"></script>