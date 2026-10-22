/**
 * Copyright (C) 2013 Loophole, LLC
 * <p>
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.manage.control;

import io.bastillion.common.util.AppConfig;
import io.bastillion.common.util.AuthUtil;
import io.bastillion.manage.db.SystemStatusDB;
import io.bastillion.manage.model.HostSystem;
import io.bastillion.manage.model.SchSession;
import io.bastillion.manage.util.DBUtils;
import io.bastillion.manage.util.SSHUtil;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import loophole.mvc.annotation.Kontrol;
import loophole.mvc.annotation.MethodType;
import loophole.mvc.annotation.Model;
import loophole.mvc.base.BaseKontroller;
import loophole.mvc.filter.SecurityFilter;
import org.apache.commons.fileupload2.core.DiskFileItemFactory;
import org.apache.commons.fileupload2.core.FileItem;
import org.apache.commons.fileupload2.jakarta.JakartaServletFileUpload;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.filefilter.AgeFileFilter;
import org.apache.commons.io.filefilter.TrueFileFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Iterator;
import java.util.List;

public class UploadAndPushKtrl extends BaseKontroller {

    private static final Logger log = LoggerFactory.getLogger(UploadAndPushKtrl.class);
    public static final String UPLOAD_PATH = AppConfig.CONFIG_DIR + "../upload";

    @Model(name = "upload")
    File upload;
    @Model(name = "uploadFileName", params = {"uploadFileName"})
    String uploadFileName;
    @Model(name = "idList", params = {"idList"})
    List<Long> idList = new ArrayList<>();
    @Model(name = "pushDir", params = {"pushDir"})
    String pushDir = "~";
    @Model(name = "hostSystemList")
    List<HostSystem> hostSystemList;
    @Model(name = "pendingSystemStatus", params = {"pendingSystemStatus.id"})
    HostSystem pendingSystemStatus;
    @Model(name = "currentSystemStatus")
    HostSystem currentSystemStatus;


    public UploadAndPushKtrl(HttpServletRequest request, HttpServletResponse response) {
        super(request, response);
    }

    @Kontrol(path = "/admin/setUpload", method = MethodType.GET)
    public String setUpload() throws Exception {
        Long userId = AuthUtil.getUserId(getRequest().getSession());

        SystemStatusDB.setInitialSystemStatus(idList, userId, AuthUtil.getUserType(getRequest().getSession()));

        return "/admin/upload.html";

    }


    @Kontrol(path = "/admin/uploadSubmit", method = MethodType.POST)
    public String uploadSubmit() {
        String retVal = "/admin/upload_result.html";

        try {
            Long userId = AuthUtil.getUserId(getRequest().getSession());

            // Factory for handling disk-based file items
            DiskFileItemFactory factory = DiskFileItemFactory.builder().get();

            // Jakarta-compatible file upload handler
            JakartaServletFileUpload uploadHandler = new JakartaServletFileUpload(factory);

            // Parse the request
            List<FileItem> items = uploadHandler.parseRequest(getRequest());

            for (FileItem item : items) {
                if (!item.isFormField()) {
                    uploadFileName = new File(item.getName()).getName();

                    File path = new File(UPLOAD_PATH);
                    if (!path.exists() && !path.mkdirs()) {
                        throw new IOException("Failed to create upload directory: " + path);
                    }

                    upload = new File(path, uploadFileName);

                    // Use NIO stream copy
                    try (var input = item.getInputStream()) {
                        java.nio.file.Files.copy(
                                input,
                                upload.toPath(),
                                java.nio.file.StandardCopyOption.REPLACE_EXISTING
                        );
                    }
                } else {
                    pushDir = item.getString();
                }
            }

            pendingSystemStatus = SystemStatusDB.getNextPendingSystem(userId);
            hostSystemList = SystemStatusDB.getAllSystemStatus(userId);

        } catch (Exception ex) {
            log.error("Upload failed", ex);
            retVal = "/admin/upload.html";
        }

        // reset csrf token since it's already set on page load
        getRequest().getSession().setAttribute(SecurityFilter._CSRF,
                getRequest().getParameter(SecurityFilter._CSRF));

        return retVal;
    }


    @Kontrol(path = "/admin/push", method = MethodType.POST)
    public String push() throws ServletException {

        // uploadFileName is bound directly from this request's own parameter (carried forward
        // as a hidden field between push iterations), not re-derived server-side - without
        // stripping it to a bare filename the same way uploadSubmit() already does, a crafted
        // value like "../../../etc/passwd" would let an already-authenticated admin read an
        // arbitrary local file (pushed via SFTP to a system they control) or delete an
        // arbitrary local file below, instead of only ever touching UPLOAD_PATH.
        if (uploadFileName != null) {
            uploadFileName = new File(uploadFileName).getName();
        }

        try {

            Long userId = AuthUtil.getUserId(getRequest().getSession());
            Long sessionId = AuthUtil.getSessionId(getRequest().getSession());

            //get next pending system
            pendingSystemStatus = SystemStatusDB.getNextPendingSystem(userId);
            if (pendingSystemStatus != null) {
                //get session for system
                SchSession session = null;
                for (Integer instanceId : SecureShellKtrl.getUserSchSessionMap().get(sessionId).getSchSessionMap().keySet()) {

                    //if host system id matches pending system then upload
                    if (pendingSystemStatus.getId().equals(SecureShellKtrl.getUserSchSessionMap().get(sessionId).getSchSessionMap().get(instanceId).getHostSystem().getId())) {
                        session = SecureShellKtrl.getUserSchSessionMap().get(sessionId).getSchSessionMap().get(instanceId);
                    }
                }

                if (session != null) {

                    //push upload to system
                    currentSystemStatus = SSHUtil.pushUpload(pendingSystemStatus, session.getSession(), UPLOAD_PATH + "/" + uploadFileName, pushDir + "/" + uploadFileName);

                    //update system status
                    SystemStatusDB.updateSystemStatus(currentSystemStatus, userId);

                    pendingSystemStatus = SystemStatusDB.getNextPendingSystem(userId);
                }

            }

            //if push has finished to all servers then delete uploaded file
            if (pendingSystemStatus == null) {
                File delFile = new File(UPLOAD_PATH, uploadFileName);
                FileUtils.deleteQuietly(delFile);


                //delete all expired files in upload path
                File delDir = new File(UPLOAD_PATH);
                if (delDir.isDirectory()) {

                    //set expire time to delete all files older than 48 hrs
                    Calendar expireTime = Calendar.getInstance();
                    expireTime.add(Calendar.HOUR, -48);

                    Iterator<File> filesToDelete = FileUtils.iterateFiles(delDir, new AgeFileFilter(expireTime.getTime()), TrueFileFilter.TRUE);
                    while (filesToDelete.hasNext()) {
                        delFile = filesToDelete.next();
                        delFile.delete();
                    }

                }

            }
            hostSystemList = SystemStatusDB.getAllSystemStatus(userId);

        } catch (SQLException | GeneralSecurityException ex) {
            log.error(ex.toString(), ex);
            throw new ServletException(ex.toString(), ex);
        }

        //reset csrf token back since it's already set on page load
        getRequest().getSession().setAttribute(SecurityFilter._CSRF,
                getRequest().getParameter(SecurityFilter._CSRF));

        return "/admin/upload_result.html";
    }

}
