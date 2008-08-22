<!-- "$Id: index.jsp 2978 2008-06-10 07:39:19Z jre $"; -->
<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
    <jsp:include page="head.jsp" />
    <h1>User info</h1>
    <br /><br />
	
	<p>This page is only available after the user has entered information at the provider.</p> 

	<p><strong>User:</strong> <%= request.getAttribute("user") %></p>
	<p><strong>Info:</strong> <%= request.getAttribute("info") %></p>
  </body>
</html>