/**
 * Copyright (C) 2013 Loophole, LLC
 * <p>
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.manage.model;

import java.util.List;

/**
 * Value object that contains host system information
 */
public class HostSystem {
    Long id;
    String displayNm;
    String user = "root";
    String host;
    Integer port = 22;
    String displayLabel;
    String authorizedKeys = "~/.ssh/authorized_keys";
    Boolean checked = false;
    String statusCd = INITIAL_STATUS;
    String errorMsg;
    String lastAuthMethod;
    List<String> publicKeyList;
    Integer instanceId;

    public static final String INITIAL_STATUS = "INITIAL";
    public static final String AUTH_FAIL_STATUS = "AUTHFAIL";
    public static final String PUBLIC_KEY_FAIL_STATUS = "KEYAUTHFAIL";
    public static final String GENERIC_FAIL_STATUS = "GENERICFAIL";
    public static final String SUCCESS_STATUS = "SUCCESS";
    public static final String HOST_FAIL_STATUS = "HOSTFAIL";
    /**
     * The system's SSH host key was refused - unknown, changed, or revoked. Distinct from
     * GENERICFAIL because it needs a specific human decision on the Host Keys screen, and
     * because "Failed" on its own is indistinguishable from a dead port or a bad password.
     */
    public static final String HOST_KEY_FAIL_STATUS = "HOSTKEYFAIL";

    /** Authenticated with a short-lived SSH certificate Bastillion signed. */
    public static final String AUTH_METHOD_CERTIFICATE = "CERTIFICATE";
    /** Authenticated with the application public key, out of the host's authorized_keys. */
    public static final String AUTH_METHOD_KEY = "KEY";


    public Long getId() {
        return id;

    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getDisplayNm() {
        return displayNm;
    }

    public void setDisplayNm(String displayNm) {
        this.displayNm = displayNm;
    }

    public String getUser() {
        return user;
    }

    public void setUser(String user) {
        this.user = user;
    }

    public String getHost() {
        return host;
    }

    public void setHost(String host) {
        this.host = host;
    }

    public String getDisplayLabel() {
        return getDisplayNm() + " - ( " + getUser() + "@" + getHost() + ":" + getPort() + " )";
    }

    public void setDisplayLabel(String displayLabel) {
        this.displayLabel = displayLabel;
    }

    public String getAuthorizedKeys() {
        return authorizedKeys;
    }

    public void setAuthorizedKeys(String authorizedKeys) {
        this.authorizedKeys = authorizedKeys;
    }

    public Integer getPort() {
        return port;
    }

    public void setPort(Integer port) {
        this.port = port;
    }

    public Boolean getChecked() {
        return checked;
    }

    public void setChecked(Boolean checked) {
        this.checked = checked;
    }

    public String getStatusCd() {
        return statusCd;
    }

    public void setStatusCd(String statusCd) {
        this.statusCd = statusCd;
    }

    public String getErrorMsg() {
        return errorMsg;
    }

    public void setErrorMsg(String errorMsg) {
        this.errorMsg = errorMsg;
    }

    public List<String> getPublicKeyList() {
        return publicKeyList;
    }

    public void setPublicKeyList(List<String> publicKeyList) {
        this.publicKeyList = publicKeyList;
    }

    /**
     * How the most recent connection to this system authenticated - see the AUTH_METHOD_*
     * constants. Null until Bastillion has connected to it since the column was added, which
     * is why the systems screen renders that as "unknown" rather than "key".
     */
    public String getLastAuthMethod() {
        return lastAuthMethod;
    }

    public void setLastAuthMethod(String lastAuthMethod) {
        this.lastAuthMethod = lastAuthMethod;
    }

    public Integer getInstanceId() {
        return instanceId;
    }

    public void setInstanceId(Integer instanceId) {
        this.instanceId = instanceId;
    }
}
