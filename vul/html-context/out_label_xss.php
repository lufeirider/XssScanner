<?php
	$url = $_GET['url'];
	$url = str_replace("'","\'",$url);
	$url = str_replace("'","\\\"",$url);
	echo "<h1>".$url."</h1>";
?>