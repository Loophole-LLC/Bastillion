/**
 * Copyright (C) 2014 Loophole, LLC
 * <p>
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.manage.control;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.WriterException;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import io.bastillion.common.util.AppConfig;
import io.bastillion.common.util.AuthUtil;
import io.bastillion.manage.db.AuthDB;
import io.bastillion.manage.db.UserDB;
import io.bastillion.manage.util.OTPUtil;
import loophole.mvc.annotation.Kontrol;
import loophole.mvc.annotation.MethodType;
import loophole.mvc.annotation.Model;
import loophole.mvc.base.BaseKontroller;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.imageio.ImageIO;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.awt.Color;
import java.awt.Graphics2D;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.net.URLEncoder;
import java.security.GeneralSecurityException;
import java.sql.SQLException;
import java.util.Date;
import java.util.Hashtable;

public class OTPKtrl extends BaseKontroller {

    private static final Logger log = LoggerFactory.getLogger(OTPKtrl.class);

    public static final boolean requireOTP = "required".equals(AppConfig.getProperty("oneTimePassword"));

    //QR image size
    private static final int QR_IMAGE_WIDTH = 325;
    private static final int QR_IMAGE_HEIGHT = 325;

    @Model(name = "qrImage", params = {"qrImage"})
    String qrImage;
    @Model(name = "sharedSecret", params = {"sharedSecret"})
    String sharedSecret;

    public OTPKtrl(HttpServletRequest request, HttpServletResponse response) {
        super(request, response);
    }

    @Kontrol(path = "/admin/viewOTP", method = MethodType.GET)
    public String viewOTP() throws ServletException {

        sharedSecret = OTPUtil.generateSecret();

        try {
            AuthUtil.setOTPSecret(getRequest().getSession(), sharedSecret);
        } catch (GeneralSecurityException ex) {
            log.error(ex.toString(), ex);
            throw new ServletException(ex.toString(), ex);
        }

        qrImage = new Date().getTime() + ".png";

        return "/admin/two-factor_otp.html";
    }

    @Kontrol(path = "/admin/otpSubmit", method = MethodType.POST)
    public String otpSubmit() throws ServletException {

        try {
            AuthDB.updateSharedSecret(sharedSecret, AuthUtil.getAuthToken(getRequest().getSession()));
        } catch (SQLException | GeneralSecurityException ex) {
            log.error(ex.toString(), ex);
            throw new ServletException(ex.toString(), ex);
        }

        if (requireOTP) {
            AuthUtil.deleteAllSession(getRequest().getSession());
        }
        return "redirect:/logout.ktrl";

    }


    @Kontrol(path = "/admin/qrImage", method = MethodType.GET)
    public String qrImage() throws ServletException {

        String username;
        String secret;
        try {
            username = UserDB.getUser(AuthUtil.getUserId(getRequest().getSession())).getUsername();
            secret = AuthUtil.getOTPSecret(getRequest().getSession());
            AuthUtil.setOTPSecret(getRequest().getSession(), null);
        } catch (SQLException | GeneralSecurityException ex) {
            log.error(ex.toString(), ex);
            throw new ServletException(ex.toString(), ex);
        }

        try {

            String qrCodeText = "otpauth://totp/Bastillion%20%28" + URLEncoder.encode(getRequest().getHeader("host").replaceAll("\\:.*$", ""), "utf-8") + "%29:" + username + "?secret=" + secret;

            QRCodeWriter qrWriter = new QRCodeWriter();

            Hashtable<EncodeHintType, String> hints = new Hashtable<>();
            hints.put(EncodeHintType.CHARACTER_SET, "UTF-8");


            BitMatrix matrix = qrWriter.encode(qrCodeText, BarcodeFormat.QR_CODE, QR_IMAGE_WIDTH, QR_IMAGE_HEIGHT, hints);
            getResponse().setContentType("image/png");

            BufferedImage image = new BufferedImage(QR_IMAGE_WIDTH, QR_IMAGE_HEIGHT, BufferedImage.TYPE_INT_RGB);

            Graphics2D graphics = (Graphics2D) image.getGraphics();
            graphics.setColor(Color.WHITE);
            graphics.fillRect(0, 0, QR_IMAGE_WIDTH, QR_IMAGE_HEIGHT);
            graphics.setColor(Color.BLACK);

            for (int x = 0; x < QR_IMAGE_WIDTH; x++) {
                for (int y = 0; y < QR_IMAGE_HEIGHT; y++) {
                    if (matrix.get(x, y)) {
                        graphics.fillRect(x, y, 1, 1);
                    }
                }
            }
            ImageIO.write(image, "png", getResponse().getOutputStream());

            getResponse().getOutputStream().flush();
            getResponse().getOutputStream().close();

        } catch (IOException | WriterException ex) {
            log.error(ex.toString(), ex);
            throw new ServletException(ex.toString(), ex);
        }

        return null;

    }
}
