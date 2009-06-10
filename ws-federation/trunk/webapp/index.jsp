<!-- "$Id: index.jsp 3180 2008-07-21 11:48:20Z jre $"; -->
<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
    <jsp:include page="head.jsp" />
    <h1>Front page - OIOSAML.java/WS-Federation Service Provider Demo</h1>
    <br /><br />

	<div style="text-align: center; float: left">
    <a href="sp/priv1.jsp">Page requiring login</a><br /><br />

<div>
<p>Test form POST:</p>
<form method="post" action="sp/post.jsp">
<input type="text" name="testing" value="testingvalue" />
<input type="submit" />
</form>
</div>    

    </div>
  </body>
</html>