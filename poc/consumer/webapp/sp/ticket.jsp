<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@page import="dk.itst.oiosaml.sp.UserAssertionHolder"%>
<%@page import="dk.itst.oiosaml.sp.service.util.Utils"%>
<%@page import="dk.itst.oiosaml.sp.util.AttributeUtil"%>
<%@page import="dk.itst.oiosaml.sp.UserAssertion"%>
<%@page import="dk.itst.oiosaml.sp.UserAttribute"%>
<jsp:include page="/head.jsp" />


<h1>STS Ticket request</h1>

<h2>EPR</h2>
<pre>
<%= Utils.beautifyAndHtmlXML((String)request.getAttribute("epr"), "&nbsp;&nbsp;&nbsp;&nbsp;") %>
</pre>

<h2>Request token</h2>
<pre>
<%= Utils.beautifyAndHtmlXML((String)request.getAttribute("request"), "&nbsp;&nbsp;&nbsp;&nbsp;") %>
</pre>

<h2>SOAP Request</h2>
<pre>
<%= Utils.beautifyAndHtmlXML((String)request.getAttribute("message"), "&nbsp;&nbsp;&nbsp;&nbsp;") %>
</pre>

<h2>Response</h2>

<p><strong>Status:</strong> <%= request.getAttribute("status") %></p>
<p><strong>Token type:</strong> <%= request.getAttribute("type") %></p>

<h3>RSTR</h3>
<pre>
<%= Utils.beautifyAndHtmlXML((String)request.getAttribute("rstr"), "&nbsp;&nbsp;&nbsp;&nbsp;") %>
</pre>
<h3>Token</h3>
<pre>
<%= Utils.beautifyAndHtmlXML((String)request.getAttribute("token"), "&nbsp;&nbsp;&nbsp;&nbsp;") %>
</pre>

<h2>SP Request</h2>
<pre>
<%= Utils.beautifyAndHtmlXML((String)request.getAttribute("spRequest"), "&nbsp;&nbsp;&nbsp;&nbsp;") %>
</pre>

<h2>SP response</h2>
<pre>
  <%= request.getAttribute("spResponse") %>
  </pre>
  
  </body>
</html>
