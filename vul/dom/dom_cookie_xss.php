<script>
	var s=location.search;
	s=s.substring(1,s.length);

	var url="";
	if(s.indexOf("url=")>-1){
		var pos=s.indexOf("url=")+4;
		url=s.substring(pos,s.length); //<--得到地址栏里的url参数
		console.log(url);
		document.cookie = "url=" + decodeURI(url);
	}else{
		document.write("url: " + document.cookie);
	}
</script>