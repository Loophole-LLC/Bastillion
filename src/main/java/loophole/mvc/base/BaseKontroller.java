/**
 * Copyright (C) 2018 Loophole, LLC
 *
 * Licensed under The Prosperity Public License 3.0.0
 */
package loophole.mvc.base;

import loophole.mvc.annotation.Kontrol;
import loophole.mvc.annotation.MethodType;
import loophole.mvc.annotation.Model;
import loophole.mvc.annotation.Validate;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.net.JarURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/**
 * Base controller class that initializes all controllers and is called through
 * the dispatcher servlet
 */
public class BaseKontroller {

    private static final String PACKAGES = System.getProperty("MVC_CONTROLLER_PKGS") != null
            ? System.getProperty("MVC_CONTROLLER_PKGS") : "";
    private static Logger log = LoggerFactory.getLogger(BaseKontroller.class);
    private static List<Class<?>> ktrlList = new ArrayList<>();

    /**
     * One annotated controller method, with the {@code validate<MethodName>} method that
     * guards it (if any) already resolved.
     *
     * @param controller      the controller class to instantiate per request
     * @param action          the {@link Kontrol}-annotated method to invoke
     * @param validator       the matching {@link Validate}-annotated method, or null
     * @param validationInput the view to forward to when validation fails
     */
    private record Route(Class<?> controller, Method action, Method validator, String validationInput) {
    }

    /**
     * Routing table, resolved once at class-load time rather than per request.
     * <p>
     * {@link #execute()} used to walk every scanned controller class and every one of its
     * methods, reading annotations reflectively, on every single request - and carried on
     * walking after it had already found and invoked a match. Resolving the annotations once
     * up front turns dispatch into a single map lookup and makes a duplicate route an
     * announced startup condition instead of "whichever method the JVM happened to return
     * last wins, after both have run".
     */
    private static final Map<String, Route> ROUTES = new HashMap<>();

    // Load scan packages for controllers that have the Kontrol method annotation
    static {
        for (String packageNm : PACKAGES.split(",")) {
            if (packageNm.isEmpty()) {
                continue;
            }
            ClassLoader classLoader = BaseKontroller.class.getClassLoader();
            String path = packageNm.replace('.', '/');
            try {
                Enumeration<URL> resources = classLoader.getResources(path);
                while (resources.hasMoreElements()) {
                    URL resource = resources.nextElement();
                    if ("jar".equals(resource.getProtocol())) {
                        // Running from a packaged jar: this package's .class files are jar
                        // entries, not files on disk - walk the jar instead of File.listFiles().
                        loadKontrollersFromJar(resource, path);
                    } else {
                        loadKontrollers(new File(resource.getFile()), packageNm);
                    }
                }
            } catch (ClassNotFoundException | IOException ex) {
                log.error(ex.toString(), ex);
            }
        }
        for (Class<?> clazz : ktrlList) {
            registerRoutes(clazz);
        }
    }

    /**
     * Indexes every {@link Kontrol} method on a controller into {@link #ROUTES}.
     */
    private static void registerRoutes(Class<?> clazz) {
        for (Method method : clazz.getMethods()) {
            Kontrol kontrol = method.getAnnotation(Kontrol.class);
            if (kontrol == null) {
                continue;
            }
            Method validator = findValidator(clazz, method);
            Route route = new Route(clazz, method, validator,
                    validator != null ? validator.getAnnotation(Validate.class).input() : null);
            String key = routeKey(kontrol.path() + DispatcherServlet.CTR_EXT, kontrol.method());
            Route existing = ROUTES.putIfAbsent(key, route);
            if (existing != null) {
                log.error("Ignoring duplicate route {} {} on {}.{} - already mapped to {}.{}",
                        kontrol.method(), kontrol.path(), clazz.getName(), method.getName(),
                        existing.controller().getName(), existing.action().getName());
            }
        }
    }

    /**
     * The {@code @Validate}-annotated method named {@code validate<ActionName>}, or null.
     */
    private static Method findValidator(Class<?> clazz, Method action) {
        for (Method candidate : clazz.getMethods()) {
            if (candidate.isAnnotationPresent(Validate.class)
                    && candidate.getName().equalsIgnoreCase("validate" + action.getName())) {
                return candidate;
            }
        }
        return null;
    }

    private static String routeKey(String servletPath, MethodType method) {
        return method.name() + ' ' + servletPath;
    }

    /**
     * Converters for the scalar field types a request parameter can be bound to.
     * <p>
     * Replaces a chain of {@code field.getType().getName().equals("java.lang.Integer")}
     * string comparisons - one branch per boxed primitive, each repeating the same
     * isEmpty-guard and {@code field.set} call.
     */
    private static final Map<Class<?>, Function<String, Object>> SCALAR_CONVERTERS = Map.of(
            Boolean.class, Boolean::parseBoolean,
            Byte.class, Byte::parseByte,
            Character.class, value -> value.charAt(0),
            Double.class, Double::parseDouble,
            Float.class, Float::parseFloat,
            Integer.class, Integer::parseInt,
            Long.class, Long::parseLong,
            Short.class, Short::parseShort);

    private List<String> errors = new ArrayList<>();
    private Map<String, String> fieldErrors = new LinkedHashMap<>();
    private HttpServletRequest request;
    private HttpServletResponse response;

    public BaseKontroller(HttpServletRequest request, HttpServletResponse response) {
        this.request = request;
        this.response = response;
    }

    private static void loadKontrollersFromJar(URL resource, String path) throws IOException, ClassNotFoundException {
        JarURLConnection conn = (JarURLConnection) resource.openConnection();
        try (JarFile jarFile = conn.getJarFile()) {
            Enumeration<JarEntry> entries = jarFile.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                String name = entry.getName();
                if (entry.isDirectory() || !name.startsWith(path + "/") || !name.endsWith(".class")) {
                    continue;
                }
                String className = name.substring(0, name.length() - ".class".length()).replace('/', '.');
                Class<?> clazz = Class.forName(className);
                if (BaseKontroller.class.equals(clazz.getSuperclass())) {
                    ktrlList.add(clazz);
                }
            }
        }
    }

    private static void loadKontrollers(File d, String packageNm) throws ClassNotFoundException {
        File[] files = d.listFiles();
        if (files != null && files.length > 0) {
            for (File file : files) {
                if (file.isDirectory()) {
                    loadKontrollers(file, packageNm + "." + file.getName());
                } else if (file.getName().endsWith(".class")) {
                    String fileNm = file.getName().replaceAll("\\.class", "");
                    if (packageNm != null && packageNm.length() > 0) {
                        fileNm = packageNm.replaceAll("^\\.", "") + '.' + fileNm;
                    }
                    Class<?> clazz = Class
                            .forName(fileNm);
                    if (BaseKontroller.class.equals(clazz.getSuperclass())) {
                        ktrlList.add(clazz);
                    }
                }
            }
        }
    }

    private static List<Field> getAllFields(Class<?> type) {
        List<Field> fields = new ArrayList<Field>();
        for (Class<?> c = type; c != null; c = c.getSuperclass()) {
            fields.addAll(Arrays.asList(c.getDeclaredFields()));
        }
        return fields;
    }

    /**
     * Find and execute controller based on annotated path
     *
     * @return page to forward / redirect
     */
    public String execute() throws ServletException {

        // Route on the container-normalized servlet path (matrix parameters like ";foo=bar"
        // stripped, "." / ".." segments resolved), matched exactly - not the raw request URI
        // with a substring contains(). AuthFilter's /manage/* and /admin/* url-pattern
        // mappings are matched by the container against this same normalized path; using the
        // raw URI with contains() here let a crafted URI like "/x;/manage/viewUsers.ktrl"
        // normalize to something AuthFilter's mapping didn't match while still containing the
        // literal controller path substring, dispatching to the real controller with no auth
        // check at all.
        MethodType methodType = toMethodType(request.getMethod());
        if (methodType == null) {
            return null;
        }
        Route route = ROUTES.get(routeKey(request.getServletPath(), methodType));
        if (route == null) {
            return null;
        }

        try {
            Constructor<?> constructor = route.controller()
                    .getDeclaredConstructor(HttpServletRequest.class, HttpServletResponse.class);
            BaseKontroller ctrl = (BaseKontroller) constructor.newInstance(request, response);

            bindModelsFromRequestAttributes(route.controller(), ctrl);

            // set parameters
            Enumeration<String> parameterNames = request.getParameterNames();
            while (parameterNames.hasMoreElements()) {
                String param = parameterNames.nextElement();
                setFieldFromParams(ctrl, param, request);
            }

            String forward = null;
            if (route.validator() != null) {
                forward = route.validationInput();
                route.validator().invoke(ctrl);
            }
            if (!ctrl.hasErrors()) {
                forward = (String) route.action().invoke(ctrl);
            }

            copyModelsToRequest(route.controller(), ctrl);

            //set errors to request
            request.setAttribute("errors", ctrl.getErrors());
            request.setAttribute("fieldErrors", ctrl.getFieldErrors());

            return forward;

        } catch (NoSuchMethodException | IllegalAccessException | InvocationTargetException | InstantiationException |
                 ClassNotFoundException ex) {
            log.error(ex.toString(), ex);
            // The full exception stays in server logs. Do not hand its class,
            // message, or cause to the container where an error renderer could
            // disclose database, filesystem, or implementation details.
            throw new ServletException("Request processing failed");
        }
    }

    /**
     * The {@link MethodType} for an HTTP method name, or null for one the enum does not
     * cover. {@code MethodType.valueOf} would instead throw IllegalArgumentException, which
     * surfaced an unmapped verb as a 500 rather than letting it fall through to a 404.
     */
    private static MethodType toMethodType(String httpMethod) {
        for (MethodType methodType : MethodType.values()) {
            if (methodType.name().equals(httpMethod)) {
                return methodType;
            }
        }
        return null;
    }

    /**
     * Seeds {@code @Model} fields from request attributes already set by an earlier forward.
     */
    private void bindModelsFromRequestAttributes(Class<?> clazz, BaseKontroller ctrl) throws IllegalAccessException {
        for (Field field : clazz.getDeclaredFields()) {
            Model model = field.getAnnotation(Model.class);
            if (model == null || model.name().isEmpty() || isNotBindable(field)) {
                continue;
            }
            Object attribute = request.getAttribute(model.name());
            if (attribute != null) {
                field.setAccessible(true);
                field.set(ctrl, attribute);
            }
        }
    }

    /**
     * Publishes the controller's {@code @Model} fields as request attributes for the view.
     */
    private void copyModelsToRequest(Class<?> clazz, BaseKontroller ctrl) throws IllegalAccessException {
        for (Field field : clazz.getDeclaredFields()) {
            Model model = field.getAnnotation(Model.class);
            if (model == null || model.name().isEmpty()) {
                continue;
            }
            field.setAccessible(true);
            Object value = field.get(ctrl);
            if (value != null) {
                request.setAttribute(model.name(), value);
            } else {
                request.setAttribute(model.name(), null);
                try {
                    request.setAttribute(model.name(), field.getType().getDeclaredConstructor().newInstance());
                } catch (ReflectiveOperationException ex) {
                    //ignore exception
                }
            }
        }
    }

    /**
     * True for a field that request parameters must never be bound into.
     * <p>
     * A static field is shared by every request and every user, so binding a parameter into
     * one is a cross-user write: {@code ?publicKey=...} against a controller holding its
     * application public key in a static {@code @Model} field would have replaced the value
     * rendered for everybody, and {@code ?someMap['k']=v} would have grown a shared map
     * without bound. A static final field is worse only in that {@code Field.set} refuses it
     * outright, turning any request that happened to name one into a 500.
     */
    private static boolean isNotBindable(Field field) {
        return Modifier.isStatic(field.getModifiers());
    }

    private void setFieldFromParams(Object ctrl, String param, HttpServletRequest request)
            throws IllegalAccessException, InstantiationException, NoSuchMethodException, InvocationTargetException, ClassNotFoundException {

        if (param == null) {
            return;
        }

        Map<String, String> requestMap = new HashMap<>();
        for (String name : param.split("\\.")) {
            for (Field field : getAllFields(ctrl.getClass())) {
                if (isNotBindable(field)) {
                    continue;
                }
                Model v = field.getAnnotation(Model.class);

                String key = null;
                if (name.contains("[")) {
                    String afterLastOpenBracket = name.substring(name.lastIndexOf("[") + 1);
                    String withoutQuotes = afterLastOpenBracket.replace("'", "");
                    int closeBracket = withoutQuotes.indexOf("]");
                    key = closeBracket >= 0 ? withoutQuotes.substring(0, closeBracket) : withoutQuotes;
                    name = name.substring(0, name.indexOf("["));
                    requestMap.put(key, request.getParameter(param));
                }
                if ((v == null && field.getName().equals(name)) || (v != null && name.equals(v.name()))) {
                    field.setAccessible(true);
                    if (!requestMap.isEmpty() && field.getType().getName().equals("java.util.Map")) {
                        setMapField(ctrl, field, requestMap);
                    } else if (field.getType().getName().equals("java.util.List") && request.getParameter(param) != null) {
                        setListField(ctrl, field, request.getParameterMap().get(param));
                    } else {
                        setScalarField(ctrl, field, param, request.getParameter(param));
                    }
                    ctrl = field.get(ctrl);
                }
            }
        }
    }

    /**
     * Populates a {@code Map<K, V>} field from bracketed parameter names (tags[env]=prod),
     * converting each key and value through the target type's String constructor.
     */
    @SuppressWarnings({"unchecked", "rawtypes"})
    private void setMapField(Object ctrl, Field field, Map<String, String> requestMap)
            throws IllegalAccessException, ClassNotFoundException, NoSuchMethodException, InstantiationException, InvocationTargetException {
        Type type = field.getGenericType();
        if (!(type instanceof ParameterizedType parameterized)) {
            return;
        }
        Type keyType = parameterized.getActualTypeArguments()[0];
        Type valueType = parameterized.getActualTypeArguments()[1];
        Map map = Map.class.cast(field.get(ctrl));
        for (Map.Entry<String, String> entry : requestMap.entrySet()) {
            Object keyOb = fromString(keyType, entry.getKey());
            Object valOb = fromString(valueType, entry.getValue());
            log.debug("Setting {} : {} -  {}", field.getName(), keyOb, valOb);
            map.put(keyOb, valOb);
        }
        field.set(ctrl, map);
    }

    /**
     * Populates a {@code List<V>} field from every value submitted for the parameter.
     */
    @SuppressWarnings({"unchecked", "rawtypes"})
    private void setListField(Object ctrl, Field field, String[] values)
            throws IllegalAccessException, ClassNotFoundException, NoSuchMethodException, InstantiationException, InvocationTargetException {
        Type type = field.getGenericType();
        if (!(type instanceof ParameterizedType parameterized) || values == null) {
            return;
        }
        Type valueType = parameterized.getActualTypeArguments()[0];
        List list = List.class.cast(field.get(ctrl));
        for (String value : values) {
            Object valOb = fromString(valueType, value);
            log.debug("Setting {} : {}", field.getName(), valOb);
            list.add(valOb);
        }
        field.set(ctrl, list);
    }

    /**
     * Binds a single parameter value to a scalar field.
     * <p>
     * A String is assigned as submitted, including empty or absent, so a cleared form field
     * clears the model. Every other scalar type only takes a non-empty value, since
     * {@code Integer.parseInt("")} would throw on an untouched form field. Anything else
     * (a nested model object) is default-constructed so the next path segment of a dotted
     * parameter name has something to descend into.
     */
    private void setScalarField(Object ctrl, Field field, String param, String value)
            throws IllegalAccessException, NoSuchMethodException, InvocationTargetException, InstantiationException {
        log.debug("Setting {} : {}", param, value);
        if (field.getType().equals(String.class)) {
            field.set(ctrl, value);
            return;
        }
        Function<String, Object> converter = SCALAR_CONVERTERS.get(field.getType());
        if (converter != null) {
            if (!StringUtils.isEmpty(value)) {
                field.set(ctrl, converter.apply(value));
            }
            return;
        }
        if (field.get(ctrl) == null) {
            field.set(ctrl, null);
            try {
                field.set(ctrl, field.getType().getDeclaredConstructor().newInstance());
            } catch (NoSuchMethodException ex) {
                //ignore exception
            }
        }
    }

    /**
     * Builds an instance of a generic type argument from its String form.
     */
    private static Object fromString(Type type, String value)
            throws ClassNotFoundException, NoSuchMethodException, InstantiationException, IllegalAccessException, InvocationTargetException {
        Class<?> theClass = Class.forName(type.getTypeName());
        Constructor<?> cons = theClass.getConstructor(String.class);
        return cons.newInstance(value);
    }

    /**
     * true if errors are set in the request
     *
     * @return true if errors
     */
    public boolean hasErrors() {
        return !(fieldErrors.isEmpty() && errors.isEmpty());
    }

    /**
     * add error to map set in request
     *
     * @param error   error name
     * @param message error message
     */
    public void addFieldError(String error, String message) {
        this.fieldErrors.put(error, message);
    }

    /**
     * add error to list set in request
     *
     * @param message error message
     */
    public void addError(String message) {
        this.errors.add(message);
    }

    /**
     * get error to set in request
     *
     * @return list of errors
     */
    public List<String> getErrors() {
        return this.errors;
    }

    /**
     * get field errors to set in request
     *
     * @return map of field errors
     */
    public Map<String, String> getFieldErrors() {
        return this.fieldErrors;
    }

    /**
     * get http servlet request
     *
     * @return http servlet request
     */
    public HttpServletRequest getRequest() {
        return request;
    }

    /**
     * set http servlet request
     *
     * @param request http servlet reqeust
     */
    public void setRequest(HttpServletRequest request) {
        this.request = request;
    }

    /**
     * get http servlet response
     *
     * @return http servlet response
     */
    public HttpServletResponse getResponse() {
        return response;
    }

    /**
     * set http servlet response
     *
     * @param response http servlet response
     */
    public void setResponse(HttpServletResponse response) {
        this.response = response;
    }

}
