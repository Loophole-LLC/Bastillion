/**
 * Copyright (C) 2018 Loophole, LLC
 *
 * Licensed under The Prosperity Public License 3.0.0
 */
package loophole.mvc.base;

import loophole.mvc.filter.SecurityFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@WebServlet("*" + DispatcherServlet.CTR_EXT)
public class DispatcherServlet extends HttpServlet {


    private static Logger log = LoggerFactory.getLogger(DispatcherServlet.class);
    public static final String CTR_EXT = ".ktrl";
    private static final long serialVersionUID = 412L;

    public DispatcherServlet() {
        super();
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        execute(request, response);
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        execute(request, response);
    }

    /**
     * Execute through base controller
     *
     * @param request  HTTP servlet request
     * @param response HTTP servlet response
     */
    private void execute(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        BaseKontroller bc = new BaseKontroller(request, response);

        String forward = bc.execute();

        if (forward != null) {
            if (forward.contains("redirect:")) {
                //add csrf to redirect
                forward = forward.contains("?") ? forward + "&" : forward + "?";
                forward = forward + SecurityFilter._CSRF + "=" + request.getSession().getAttribute(SecurityFilter._CSRF);
                forward = request.getContextPath() + forward.replaceAll("redirect:", "");
                log.debug("redirect : " + forward);
                response.sendRedirect(forward);

            } else {
                forward = forward.replaceAll("forward:", "");
                log.debug("forward: " + forward);
                request.getRequestDispatcher(forward)
                        .forward(request, response);
            }
        } else if (!response.isCommitted()) {
            // A null forward with no response written is a genuine "no matching view" - but
            // some controllers (OTPKtrl.qrImage, AuthKeysKtrl.downloadPvtKey,
            // SessionAuditKtrl.streamTermOutputForSession) write their own response body
            // directly and return null on success. isCommitted() tells those two cases
            // apart; without this check, sendError() on an already-flushed-and-closed
            // response throws IllegalStateException("COMPLETED") even though the response
            // was already sent to the client successfully.
            response.sendError(HttpServletResponse.SC_NOT_FOUND);
        }

    }
}