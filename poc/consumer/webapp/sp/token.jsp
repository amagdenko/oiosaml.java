<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@page import="dk.itst.oiosaml.sp.UserAssertionHolder"%>
<%@page import="dk.itst.oiosaml.sp.service.util.Utils"%>
<%@page import="dk.itst.oiosaml.sp.util.AttributeUtil"%>
<%@page import="dk.itst.oiosaml.sp.UserAssertion"%>
<%@page import="dk.itst.oiosaml.sp.UserAttribute"%>
<jsp:include page="/head.jsp" />


<h1>STS Ticket request</h1>

<h2>SP Request</h2>
<pre>
<%= request.getAttribute("spRequest") %>
</pre>

<h2>SP response</h2>
<pre>
  <%= request.getAttribute("spResponse") %>
  </pre>
  
  </body>
</html>
