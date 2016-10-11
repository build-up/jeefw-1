package com.jeefw.controller.sys;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.net.URLDecoder;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import core.util.RandomUtils;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.apache.commons.beanutils.ConvertUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.time.DateFormatUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.commons.mail.DefaultAuthenticator;
import org.apache.commons.mail.SimpleEmail;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.crypto.hash.Sha256Hash;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.support.RequestContext;
import com.jeefw.core.Constant;
import com.jeefw.core.JavaEEFrameworkBaseController;
import com.jeefw.model.sys.Attachment;
import com.jeefw.model.sys.Authority;
import com.jeefw.model.sys.Role;
import com.jeefw.model.sys.SysUser;
import com.jeefw.service.sys.AttachmentService;
import com.jeefw.service.sys.AuthorityService;
import com.jeefw.service.sys.RoleService;
import com.jeefw.service.sys.SysUserService;
import core.support.ExtJSBaseParameter;
import core.support.JqGridPageView;
import core.support.QueryResult;
import core.util.JavaEEFrameworkUtils;

/**
 * 用户的控制层
 */
@Controller
@RequestMapping("/sys/sysuser")
public class SysUserController extends JavaEEFrameworkBaseController<SysUser> implements Constant {

	private static final Log log = LogFactory.getLog(SysUserController.class);
	@Resource
	private SysUserService sysUserService;
	@Resource
	private AttachmentService attachmentService;
	@Resource
	private AuthorityService authorityService;
	@Resource
	private RoleService roleService;

	private static SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");

	// 1.登录
	@RequestMapping("/login")
	public void login(SysUser sysUserModel, HttpServletRequest request, HttpServletResponse response) throws IOException {
		Map<String, Object> result = new HashMap<String, Object>();
		SysUser sysUser = sysUserService.getByProerties("email", sysUserModel.getEmail());
		if (sysUser == null || sysUser.getStatus() == true) { // 用户名有误或已被禁用
			result.put("result", -1);
			writeJSON(response, result);  //返回json数据。
			return;
		}
        //这里是使用了sha256hash的加密。和从数据库查询出来的数据进行比较
		if (!sysUser.getPassword().equals(new Sha256Hash(sysUserModel.getPassword()).toHex())) { // 密码错误
			result.put("result", -2);
			writeJSON(response, result);
			return;
		}
		sysUser.setLastLoginTime(new Date());
		sysUserService.merge(sysUser);  //融合到sysUser。因为上面设置了sysUser的最后登录时间。
		Subject subject = SecurityUtils.getSubject();
		subject.login(new UsernamePasswordToken(sysUserModel.getEmail(), sysUserModel.getPassword(), sysUserModel.isRememberMe()));
		Session session = subject.getSession();
		session.setAttribute(SESSION_SYS_USER, sysUser);
		session.setAttribute("ROLE_KEY", sysUser.getRoles().iterator().next().getRoleKey());
		result.put("result", 1);
		writeJSON(response, result);
	}

	// 2.跳转到主页，获取菜单并授权
	@RequestMapping("/home")
	public ModelAndView home(HttpServletRequest request, HttpServletResponse response) {
		Subject subject = SecurityUtils.getSubject();
		Session session = subject.getSession();
		if (session.getAttribute(SESSION_SYS_USER) == null) {
			return new ModelAndView();
		} else {
			SysUser sysUser = (SysUser) session.getAttribute(SESSION_SYS_USER);
			String globalRoleKey = sysUser.getRoles().iterator().next().getRoleKey();
			try {
				List<Authority> allMenuList = authorityService.queryAllMenuList(globalRoleKey);
                //请求转发。所以地址栏的地址应该是。/sys/sysuser/home.
				return new ModelAndView("back/index", "authorityList", allMenuList);
			} catch (Exception e) {
				log.error(e.toString());
				return new ModelAndView();
			}
		}
	}

	// 3.注册
	@RequestMapping("/register")
	public void register(SysUser sysUserModel, HttpServletRequest request, HttpServletResponse response) throws IOException {
		Map<String, Object> result = new HashMap<String, Object>();
		SysUser emailSysUser = sysUserService.getByProerties("email", sysUserModel.getEmail());
		if (emailSysUser != null) {
			result.put("result", -1);
			writeJSON(response, result);
			return;
		}
		SysUser sysUser = new SysUser();
		sysUser.setUserName(sysUserModel.getUserName());
		sysUser.setSex(sysUserModel.getSex());
		sysUser.setEmail(sysUserModel.getEmail());
		sysUser.setPhone(sysUserModel.getPhone());
		sysUser.setBirthday(sysUserModel.getBirthday());
		// sysUser.setPassword(MD5.crypt(sysUserModel.getPassword()));
		sysUser.setPassword(new Sha256Hash(sysUserModel.getPassword()).toHex());//对密码进行加密
		sysUser.setStatus(false);
		sysUser.setLastLoginTime(new Date());

		Set<Role> roles = new HashSet<Role>();
        //查询出“普通会员”的role对象，实际上是得到这个role的id。
		Role role = roleService.getByProerties("roleKey", "ROLE_USER");
		roles.add(role);
		sysUser.setRoles(roles); //sysUser这边维护关联关系，所以当设置lesysUser的roles会向sysuser_role表存放一条数据。

		sysUserService.persist(sysUser);
		// sysUserService.saveSysuserAndRole(sysUser.getId(), 3);

		Subject subject = SecurityUtils.getSubject();
		subject.login(new UsernamePasswordToken(sysUserModel.getEmail(), sysUserModel.getPassword()));
		Session session = subject.getSession();
		session.setAttribute(SESSION_SYS_USER, sysUser);
		session.setAttribute("ROLE_KEY", sysUser.getRoles().iterator().next().getRoleKey());

		result.put("result", 1);
		writeJSON(response, result);
	}

	// 4.获取个人资料信息
	@RequestMapping("/sysuserprofile")
	public ModelAndView sysuserprofile(HttpServletRequest request, HttpServletResponse response) throws IOException {
        //获取个人资料信息（只是用户的信息）
        SysUser sysuser = sysUserService.get(((SysUser) request.getSession().getAttribute(SESSION_SYS_USER)).getId());
		//获取个人资料信息（将数据库查询出来的信息再处理，增加头像）
        SysUser sysUserWithAvatar = sysUserService.getSysUserWithAvatar(sysuser);
		return new ModelAndView("back/sysuserprofile", "sysuser", sysUserWithAvatar);
	}

	// 5.登出
	@RequestMapping("/logout")
	public void logout(HttpServletRequest request, HttpServletResponse response) throws IOException {
		SecurityUtils.getSubject().logout();
		response.sendRedirect("/jeefw/login.jsp");
	}

	// 6.发送邮件找回密码
	@RequestMapping("/retrievePassword")
	public void retrievePassword(HttpServletRequest request, HttpServletResponse response) throws IOException {
		Map<String, Object> result = new HashMap<String, Object>();
		String email = request.getParameter("email");
		SysUser sysUser = sysUserService.getByProerties("email", email);
		if (sysUser == null || sysUser.getStatus() == true) { // 用户名有误或已被禁用
			result.put("result", -1);
			writeJSON(response, result);
			return;
		}
		SimpleEmail emailUtil = new SimpleEmail();
		emailUtil.setCharset("utf-8");
        //emailUtil.setHostName("smtp.sohu.com");
        emailUtil.setHostName("smtp.163.com");
		try {
			emailUtil.addTo(email, sysUser.getUserName());
			//现在使用sohu的邮箱。
            //emailUtil.setAuthenticator(new DefaultAuthenticator("llsydn@sohu.com","428527")); // 参数是您的真实邮箱和密码
            //emailUtil.setFrom("llsydn@sohu.com","儿童游艺管理系统");

            //使用163邮箱
            emailUtil.setAuthenticator(new DefaultAuthenticator("13543844606@163.com","llsydn428527")); //后面的参数是163邮箱的授权码
            emailUtil.setFrom("13543844606@163.com","儿童游艺管理员");

            emailUtil.setSubject("儿童游艺管理系统密码找回");

            //重新设置登录密码
            Long id = sysUser.getId();
            String password= RandomUtils.generateString(6);  //随机生成一个6位长的字符串，作为登录的密码
            sysUserService.updateByProperties("id", id, "password", new Sha256Hash(password).toHex());

			emailUtil.setMsg("儿童游艺管理系统的用户:" + sysUser.getUserName() + ",您的登录密码是:" + password +"请不要告诉别人,希望能够妥善保管.^_^");
            //判断邮件是否发送成功
            emailUtil.send();

		} catch (Exception e) {
			e.printStackTrace();
            result.put("result",-2);
            writeJSON(response, result);
            return;
		}
        result.put("result", 1);
		writeJSON(response, result);
	}

	// 7.更改密码
	@RequestMapping("/resetPassword")
	public void resetPassword(HttpServletRequest request, HttpServletResponse response) throws IOException {
		String password = request.getParameter("password");
		Long id = ((SysUser) request.getSession().getAttribute(SESSION_SYS_USER)).getId();
		// sysUserService.updateByProperties("id", id, "password", MD5.crypt(password));
		sysUserService.updateByProperties("id", id, "password", new Sha256Hash(password).toHex());
		Map<String, Object> result = new HashMap<String, Object>();
		result.put("success", true);
		writeJSON(response, result);
	}

	// 8.查询用户的表格，包括分页、搜索和排序
	@RequestMapping(value = "/getSysUser", method = { RequestMethod.POST, RequestMethod.GET })
	public void getSysUser(HttpServletRequest request, HttpServletResponse response) throws Exception {
		Integer firstResult = Integer.valueOf(request.getParameter("page")); //第几页
		Integer maxResults = Integer.valueOf(request.getParameter("rows"));  //每页显示多少行
		String sortedObject = request.getParameter("sidx");                  //根据什么查询
		String sortedValue = request.getParameter("sord");                   //以升序还是降序的方式排序
		String filters = request.getParameter("filters");                    //过滤。(不知道干嘛)

        SysUser sysUser = new SysUser();

        if (StringUtils.isNotBlank(filters)) {   //判断一个字符串是不为空，空就返回false，不为空就返回true
			JSONObject jsonObject = JSONObject.fromObject(filters);
			JSONArray jsonArray = (JSONArray) jsonObject.get("rules");
			for (int i = 0; i < jsonArray.size(); i++) {
				JSONObject result = (JSONObject) jsonArray.get(i);
				if (result.getString("field").equals("email") && result.getString("op").equals("eq")) {
					sysUser.set$eq_email(result.getString("data"));
				}
				if (result.getString("field").equals("userName") && result.getString("op").equals("cn")) {
					sysUser.set$like_userName(result.getString("data"));
				}
			}
			if (((String) jsonObject.get("groupOp")).equalsIgnoreCase("OR")) {
				sysUser.setFlag("OR");
			} else {
				sysUser.setFlag("AND");
			}
		}
        //因为SysUser是BaseParameter的子类。
		sysUser.setFirstResult((firstResult - 1) * maxResults);                   //设置开始的位置。
		sysUser.setMaxResults(maxResults);                                        //设置最大。
		Map<String, String> sortedCondition = new HashMap<String, String>();
		sortedCondition.put(sortedObject, sortedValue);                           //根据id的asc升序，查询。
		sysUser.setSortedConditions(sortedCondition);                             //设置查询条件。

        //根据各种查询条件返回分页列表
        QueryResult<SysUser> queryResult = sysUserService.doPaginationQuery(sysUser);

        JqGridPageView<SysUser> sysUserListView = new JqGridPageView<SysUser>();
		sysUserListView.setMaxResults(maxResults);

        //获取用户信息（将数据库查询出来的信息再处理，增加字段的中文意思）
        List<SysUser> sysUserCnList = sysUserService.querySysUserCnList(queryResult.getResultList());

        sysUserListView.setRows(sysUserCnList);                    //设置sysUserListView的rows记录
		sysUserListView.setRecords(queryResult.getTotalCount());   //设置sysUserListView的总的记录数

        //把查询出来的sysUserListView，保存在response中。
		writeJSON(response, sysUserListView);
	}

	// 9.保存用户的实体Bean
	@RequestMapping(value = "/saveSysUser", method = { RequestMethod.POST, RequestMethod.GET })
	public void doSave(SysUser entity, HttpServletRequest request, HttpServletResponse response) throws IOException {

        ExtJSBaseParameter parameter = ((ExtJSBaseParameter) entity);
		//编辑，修改一个用户的信息
        if (CMD_EDIT.equals(parameter.getCmd())) {
			SysUser sysUser = sysUserService.get(entity.getId());
			entity.setPassword(sysUser.getPassword());
			entity.setLastLoginTime(sysUser.getLastLoginTime());
			sysUserService.merge(entity);  //因为sysuser和role是多对多的关系，所以在保存的时候，同时也会关联到role，sysuser_role等表

		} else if (CMD_NEW.equals(parameter.getCmd())) {  //创建一个新的用户。
			// entity.setPassword(MD5.crypt("123456")); // 初始化密码为123456
			entity.setPassword(new Sha256Hash("123456").toHex()); // 初始化密码为123456
			sysUserService.persist(entity);
		}
		parameter.setSuccess(true);
		writeJSON(response, parameter);
	}

	// 10.操作用户的删除、导出Excel、字段判断和保存
	@RequestMapping(value = "/operateSysUser", method = { RequestMethod.POST, RequestMethod.GET })
	public void operateSysUser(HttpServletRequest request, HttpServletResponse response) throws Exception {
		String oper = request.getParameter("oper");
		String id = request.getParameter("id");
		if (oper.equals("del")) {  //删除一个用户
			String[] ids = id.split(",");
			deleteSysUser(request, response, (Long[]) ConvertUtils.convert(ids, Long.class));
		} else if (oper.equals("excel")) {   //导出excel表
            response.setCharacterEncoding("UTF-8");
            response.setContentType("application/msexcel;charset=UTF-8");
			try {
				response.addHeader("Content-Disposition", "attachment;filename=file.xls");
				OutputStream out = response.getOutputStream();
				out.write(URLDecoder.decode(request.getParameter("csvBuffer"), "UTF-8").getBytes());
				out.flush();
				out.close();
			} catch (Exception e) {
				e.printStackTrace();
			}
		} else {   //其他的操作
			Map<String, Object> result = new HashMap<String, Object>();
			String userName = request.getParameter("userName");
			String email = request.getParameter("email");
			SysUser sysUser = null;
			if (oper.equals("edit")) {   //编辑操作
                //通过id，获取sysuser对象
				sysUser = sysUserService.get(Long.valueOf(id));
			}

            //通过邮箱，获取sysuser对象
			SysUser emailSysUser = sysUserService.getByProerties("email", email);

			if (StringUtils.isBlank(userName) || StringUtils.isBlank(email)) { //isBlank判断一个字符串是否为空
				response.setStatus(HttpServletResponse.SC_LENGTH_REQUIRED);
				result.put("message", "请填写姓名和邮箱");
				writeJSON(response, result);
			} else if (null != emailSysUser && oper.equals("add")) {
				response.setStatus(HttpServletResponse.SC_CONFLICT);
				result.put("message", "此邮箱已存在，请重新输入");
				writeJSON(response, result);
			} else if (null != emailSysUser && !sysUser.getEmail().equalsIgnoreCase(email) && oper.equals("edit")) {
				response.setStatus(HttpServletResponse.SC_CONFLICT);
				result.put("message", "此邮箱已存在，请重新输入");
				writeJSON(response, result);
			} else {
				SysUser entity = new SysUser();
				entity.setUserName(userName);
				entity.setSex(Short.valueOf(request.getParameter("sexCn")));
				entity.setEmail(email);
				entity.setPhone(request.getParameter("phone"));
				if (StringUtils.isNotBlank(request.getParameter("birthday"))) {
					entity.setBirthday(dateFormat.parse(request.getParameter("birthday")));
				}
				entity.setDepartmentKey(request.getParameter("departmentValue"));
				entity.setStatusCn(request.getParameter("statusCn"));
				if (entity.getStatusCn().equals("是")) {
					entity.setStatus(true);
				} else {
					entity.setStatus(false);
				}

				Set<Role> roles = new HashSet<Role>();
				Role role = roleService.getByProerties("roleKey", request.getParameter("roleCn"));
				roles.add(role);
				entity.setRoles(roles);

				if (oper.equals("edit")) {

					entity.setId(Long.valueOf(id));
					entity.setCmd("edit");
                    //这个是调用上面的 方法9
					doSave(entity, request, response);

				} else if (oper.equals("add")) {

					entity.setCmd("new");
					doSave(entity, request, response);

				}
			}
		}
	}

	// 11.保存个人资料
	@RequestMapping(value = "/saveSysUserProfile", method = { RequestMethod.POST, RequestMethod.GET })
	public void saveSysUserProfile(HttpServletRequest request, HttpServletResponse response) throws Exception {
		Long sysUserId = ((SysUser) request.getSession().getAttribute(SESSION_SYS_USER)).getId();
		SysUser sysUser = sysUserService.get(sysUserId);
		SysUser entity = new SysUser();
		entity.setId(sysUserId);
		entity.setUserName(request.getParameter("userName"));
		entity.setSex(Short.valueOf(request.getParameter("sex")));
		entity.setEmail(request.getParameter("email"));
		entity.setPhone(request.getParameter("phone"));
		if (null != request.getParameter("birthday")) {
			entity.setBirthday(dateFormat.parse(request.getParameter("birthday")));
		}
		entity.setStatus(sysUser.getStatus());
		entity.setPassword(sysUser.getPassword());
		entity.setLastLoginTime(sysUser.getLastLoginTime());
		entity.setDepartmentKey(sysUser.getDepartmentKey());
		entity.setRoles(sysUser.getRoles());
		sysUserService.merge(entity);
		Map<String, Object> result = new HashMap<String, Object>();
		result.put("success", true);
		writeJSON(response, result);
	}

	//12. 删除用户
	@RequestMapping("/deleteSysUser")
	public void deleteSysUser(HttpServletRequest request, HttpServletResponse response, @RequestParam("ids") Long[] ids) throws IOException {
		if (Arrays.asList(ids).contains(Long.valueOf("1"))) {

			writeJSON(response, "{success:false,message:'删除项包含超级管理员，超级管理员不能删除！'}");
		} else {
			boolean flag = sysUserService.deleteByPK(ids);
			if (flag) {
				writeJSON(response, "{success:true}");
			} else {
				writeJSON(response, "{success:false}");
			}
		}
	}

	// 13.即时更新个人资料的字段
	@RequestMapping(value = "/updateSysUserField", method = { RequestMethod.POST, RequestMethod.GET })
	public void updateSysUserField(HttpServletRequest request, HttpServletResponse response) throws Exception {
		Long id = Long.valueOf(request.getParameter("pk"));
		String name = request.getParameter("name");
		String value = request.getParameter("value");
		if (name.equals("userName")) {
			sysUserService.updateByProperties("id", id, "userName", value);
		} else if (name.equals("sex")) {
			sysUserService.updateByProperties("id", id, "sex", Short.valueOf(value));
		} else if (name.equals("email")) {
			sysUserService.updateByProperties("id", id, "email", value);
		} else if (name.equals("phone")) {
			sysUserService.updateByProperties("id", id, "phone", value);
		} else if (name.equals("birthday")) {
			if (null != value) {
                //因为网页提交过来的数据是yyyy-MM-dd,而我们数据库里面的数据是有时分秒的,所以要转换格式
				sysUserService.updateByProperties("id", id, "birthday", dateFormat.parse(value));
			}
		}
	}
	private static SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMddHHmmssSSS");

	// 14.上传个人资料的头像
	@RequestMapping(value = "/uploadAttachement", method = RequestMethod.POST)
	public void uploadAttachement(@RequestParam(value = "avatar", required = false) MultipartFile file, HttpServletRequest request, HttpServletResponse response) throws Exception {
		RequestContext requestContext = new RequestContext(request);
		JSONObject json = new JSONObject();
		if (!file.isEmpty()) {
			if (file.getSize() > 2097152) {
				json.put("message", requestContext.getMessage("g_fileTooLarge"));
			} else {
				try {
                    //获取文件的原名称
					String originalFilename = file.getOriginalFilename();
					//设置文件保存名称(日期+(3位随机数)+文件后缀名)
                    String fileName = sdf.format(new Date()) + JavaEEFrameworkUtils.getRandomString(3) +
                            originalFilename.substring(originalFilename.lastIndexOf("."));
					//设置文件保存路径
                    File filePath = new File(getClass().getClassLoader().getResource("/").getPath().
                            replace("/WEB-INF/classes/artifacts/jeefw_Web_exploded/WEB-INF/classes", "/static/upload/img/" + DateFormatUtils.format(new Date(), "yyyyMM")));
					if (!filePath.exists()) {
						filePath.mkdirs();
					}
                    //把文件拷贝到指定绝对路径下面。
					file.transferTo(new File(filePath.getAbsolutePath() + "\\" + fileName));
					//设置目标路径，就是相对路径。
                    String destinationFilePath = "/static/upload/img/" + DateFormatUtils.format(new Date(), "yyyyMM") + "/" + fileName;

                    //先获取用户的id。
                    Long sysUserId = ((SysUser) request.getSession().getAttribute(SESSION_SYS_USER)).getId();
					//通过type和typeId,删除attachment里面的数据。typeId是用户的id。
                    attachmentService.deleteByProperties(new String[] { "type", "typeId" }, new Object[] { (short) 1, sysUserId });

                    //设置一个attachment对象。
                    Attachment attachment = new Attachment();
					attachment.setFileName(originalFilename);
					attachment.setFilePath(destinationFilePath);
					attachment.setType((short) 1);
					attachment.setTypeId(sysUserId);
					attachmentService.persist(attachment); //保存到数据库

					json.put("status", "OK");
					json.put("url", request.getContextPath() + destinationFilePath);
					json.put("message", requestContext.getMessage("g_uploadSuccess"));//上传成功
				} catch (Exception e) {
					e.printStackTrace();
					json.put("message", requestContext.getMessage("g_uploadFailure"));//上传失败
				}
			}
		} else {
			json.put("message", requestContext.getMessage("g_uploadNotExists"));//上传文件不存在
		}
		writeJSON(response, json.toString());
	}

	/** 以下方法是根据路径跳转到页面 **/

	@RequestMapping("/sysuser")
	public String sysuser(HttpServletRequest request, HttpServletResponse response) throws IOException {
		return "back/systemmanage/sysuser";
	}

    /*在登录跳转后，会去到index.jsp,但是过程中会调用ajax,请求了/homepage,所以会向页面相应homepage页面*/
	@RequestMapping("/homepage")
	public String homepage(HttpServletRequest request, HttpServletResponse response) throws IOException {
		return "back/homepage";
	}

	@RequestMapping("/dict")
	public String dict(HttpServletRequest request, HttpServletResponse response) throws IOException {
		return "back/systemmanage/dict";
	}

	@RequestMapping("/role")
	public String role(HttpServletRequest request, HttpServletResponse response) throws IOException {
		return "back/systemmanage/role";
	}

	@RequestMapping("/department")
	public String department(HttpServletRequest request, HttpServletResponse response) throws IOException {
		return "back/systemmanage/department";
	}

	@RequestMapping("/mail")
	public String mail(HttpServletRequest request, HttpServletResponse response) throws IOException {
		return "back/systemmanage/mail";
	}

	@RequestMapping("/information")
	public String information(HttpServletRequest request, HttpServletResponse response) throws IOException {
		return "back/infomanage/information";
	}

	@RequestMapping("/authority")
	public String authority(HttpServletRequest request, HttpServletResponse response) throws IOException {
		return "back/systemmanage/authority";
	}

	@RequestMapping("/typography")
	public String typography(HttpServletRequest request, HttpServletResponse response) throws IOException {
		return "back/bootstrapexample/typography";
	}

	@RequestMapping("/uielements")
	public String uielements(HttpServletRequest request, HttpServletResponse response) throws IOException {
		return "back/bootstrapexample/uielements";
	}

	@RequestMapping("/buttonsicon")
	public String buttonsicon(HttpServletRequest request, HttpServletResponse response) throws IOException {
		return "back/bootstrapexample/buttonsicon";
	}

	@RequestMapping("/contentslider")
	public String contentslider(HttpServletRequest request, HttpServletResponse response) throws IOException {
		return "back/bootstrapexample/contentslider";
	}

	@RequestMapping("/nestablelist")
	public String nestablelist(HttpServletRequest request, HttpServletResponse response) throws IOException {
		return "back/bootstrapexample/nestablelist";
	}

	@RequestMapping("/jquerydatatables")
	public String jquerydatatables(HttpServletRequest request, HttpServletResponse response) throws IOException {
		return "back/bootstrapexample/jquerydatatables";
	}

	@RequestMapping("/formelements")
	public String formelements(HttpServletRequest request, HttpServletResponse response) throws IOException {
		return "back/bootstrapexample/formelements";
	}

	@RequestMapping("/formelements2")
	public String formelements2(HttpServletRequest request, HttpServletResponse response) throws IOException {
		return "back/bootstrapexample/formelements2";
	}

	@RequestMapping("/wizardvalidation")
	public String wizardvalidation(HttpServletRequest request, HttpServletResponse response) throws IOException {
		return "back/bootstrapexample/wizardvalidation";
	}

	@RequestMapping("/uiwidgets")
	public String uiwidgets(HttpServletRequest request, HttpServletResponse response) throws IOException {
		return "back/bootstrapexample/uiwidgets";
	}

	@RequestMapping("/calendar")
	public String calendar(HttpServletRequest request, HttpServletResponse response) throws IOException {
		return "back/bootstrapexample/calendar";
	}

	@RequestMapping("/gallery")
	public String gallery(HttpServletRequest request, HttpServletResponse response) throws IOException {
		return "back/bootstrapexample/gallery";
	}

	@RequestMapping("/pricingtables")
	public String pricingtables(HttpServletRequest request, HttpServletResponse response) throws IOException {
		return "back/bootstrapexample/pricingtables";
	}

	@RequestMapping("/invoice")
	public String invoice(HttpServletRequest request, HttpServletResponse response) throws IOException {
		return "back/bootstrapexample/invoice";
	}

	@RequestMapping("/timeline")
	public String timeline(HttpServletRequest request, HttpServletResponse response) throws IOException {
		return "back/bootstrapexample/timeline";
	}

	@RequestMapping("/faq")
	public String faq(HttpServletRequest request, HttpServletResponse response) throws IOException {
		return "back/bootstrapexample/faq";
	}

	@RequestMapping("/grid")
	public String grid(HttpServletRequest request, HttpServletResponse response) throws IOException {
		return "back/bootstrapexample/grid";
	}

	@RequestMapping("/charts")
	public String charts(HttpServletRequest request, HttpServletResponse response) throws IOException {
		return "back/chartandreport/charts";
	}

	@RequestMapping("/callError404")
	public String callError404(HttpServletRequest request, HttpServletResponse response) throws IOException {
		return "redirect:/sys/sysuser/error404";
	}

	@RequestMapping("/error404")
	public String error404(HttpServletRequest request, HttpServletResponse response) throws IOException {
		return "back/error404";
	}

	@RequestMapping("/callError500")
	public String callError500(HttpServletRequest request, HttpServletResponse response) throws IOException {
		return "redirect:/sys/sysuser/error500";
	}

	@RequestMapping("/error500")
	public String error500(HttpServletRequest request, HttpServletResponse response) throws IOException {
		return "back/error500";
	}

	@RequestMapping("/callUnauthorized")
	public String callUnauthorized(HttpServletRequest request, HttpServletResponse response) throws IOException {
		return "redirect:/sys/sysuser/unauthorized";
	}

	@RequestMapping("/unauthorized")
	public String unauthorized(HttpServletRequest request, HttpServletResponse response) throws IOException {
		return "back/unauthorized";
	}

	@RequestMapping("/druid")
	public String druid(HttpServletRequest request, HttpServletResponse response) throws IOException {
		return "back/druid";
	}

}
