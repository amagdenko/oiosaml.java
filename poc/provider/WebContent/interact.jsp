<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">

<%@page import="dk.itst.oiosaml.sp.UserAssertionHolder"%><html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<title>Insert title here</title>
</head>
<body>

<h1>Welcome, <%= UserAssertionHolder.get().getSubject() %>!</h1>

<p>Please enter info below: <br />
<form method="post" action="interact">
<input type="text" name="info" /><br />
<input type="submit" value="Send" />

<input type="hidden" name="ReturnToURL" value="<%= request.getParameter("ReturnToURL") %>" />
</form>
</p>
</body>
</html>
