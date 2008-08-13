package dk.itst.saml.poc.provider;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import dk.itst.oiosaml.sp.UserAssertionHolder;

/**
 * Servlet implementation class InteractServlet
 */
public class InteractServlet extends HttpServlet {

	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		String info = request.getParameter("info");
		String user = UserAssertionHolder.get().getSubject();
		
		InfoRepository.setInfo(user, info);
		
		response.sendRedirect(request.getParameter("ReturnToURL"));
	}

}
