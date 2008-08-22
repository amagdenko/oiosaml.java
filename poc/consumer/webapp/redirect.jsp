<!-- "$Id: index.jsp 2978 2008-06-10 07:39:19Z jre $"; -->
<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
    <jsp:include page="head.jsp" />
    <h1>Interaction required</h1>
    <br /><br />

	<p>In order to complete the request <%= request.getAttribute("request")  %> at service <%= request.getAttribute("service") %>, you need to 
	provide additional information directly to the service.</p>

	<p>Message from the service:<br />
	<strong><%= request.getAttribute("message") %></strong></p>

	<p>To complete the process, please go to<br />
	<strong><a href="<%= request.getAttribute("url") %>"><%= request.getAttribute("url") %></a></strong></p>

	<p>When you have provided the additional information, the request will be resumed automatically.</p>
  </body>
</html>