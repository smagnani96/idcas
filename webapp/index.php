<html>
 <head>
  <title>PHP Example app</title>
 </head>
 <body>
 <?php 
 if(isset($_GET["secret"]) && $_GET["secret"] == 1) 
 	echo 'Congratulations! The flag is: myFlg{ZmxhZw==}'; 
 ?> 
 </body>
</html>