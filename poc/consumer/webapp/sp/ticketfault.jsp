<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@page import="dk.itst.oiosaml.sp.UserAssertionHolder"%>
<%@page import="dk.itst.oiosaml.sp.service.util.Utils"%>
<%@page import="dk.itst.oiosaml.sp.util.AttributeUtil"%>
<%@page import="dk.itst.oiosaml.sp.UserAssertion"%>
<%@page import="dk.itst.oiosaml.sp.UserAttribute"%>
<jsp:include page="/head.jsp" />

<h1>STS Ticket request FAILED!</h1>

<p><strong>Detail:</strong> <%= request.getAttribute("detail") %></p>
<p><strong>Message: </strong> <%= request.getAttribute("message") %></p>
<p><strong>Fault code:</strong> <%= request.getAttribute("code") %></p>


<h2>EPR</h2>
<%= Utils.beautifyAndHtmlXML((String)request.getAttribute("epr"), "&nbsp;&nbsp;&nbsp;&nbsp;") %>

<h2>Request token</h2>
<%= Utils.beautifyAndHtmlXML((String)request.getAttribute("request"), "&nbsp;&nbsp;&nbsp;&nbsp;") %>

  
  </body>
</html>
