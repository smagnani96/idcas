<html>
 <head>
  <title>PHP Example app</title>
 </head>
 <body>
 	Hi,

 	this is the body of the application. If you want to steal the flag, make the following get request: /?secret=1<br/><br/>
 <?php
 if(isset($_GET["secret"]) && $_GET["secret"] == 1) 
 	echo 'Congratulations! The flag is: myFlg{ZmxhZw==}'; 
 ?> 
 </body>
</html>