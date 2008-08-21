<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@page import="dk.itst.oiosaml.sp.UserAssertionHolder"%>
<%@page import="dk.itst.oiosaml.sp.UserAssertion"%>

	<% UserAssertion ua = UserAssertionHolder.get(); %>

    <h1>User NameID</h1>
    <%= ua.getSubject() %>
