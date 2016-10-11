package com.jeefw.controller.sys;

import java.io.IOException;
import java.io.OutputStream;
import java.net.URLDecoder;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

import org.apache.commons.beanutils.ConvertUtils;
import org.apache.commons.lang.StringUtils;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

import com.jeefw.core.Constant;
import com.jeefw.core.JavaEEFrameworkBaseController;
import com.jeefw.model.sys.Role;
import com.jeefw.service.sys.RoleService;
import com.jeefw.service.sys.SysUserService;

import core.support.ExtJSBaseParameter;
import core.support.JqGridPageView;
import core.support.QueryResult;

/**
 * 角色的控制层
 *
 */
@Controller
@RequestMapping("/sys/role")
public class RoleController extends JavaEEFrameworkBaseController<Role> implements Constant {

	@Resource
	private RoleService roleService;
	@Resource
	private SysUserService sysUserService;

	// 1.查询角色的表格，包括分页、搜索和排序
	@RequestMapping(value = "/getRole", method = { RequestMethod.POST, RequestMethod.GET })
	public void getRole(HttpServletRequest request, HttpServletResponse response) throws Exception {
        Integer firstResult = Integer.valueOf(request.getParameter("page"));  //获取要显示第几页
		Integer maxResults = Integer.valueOf(request.getParameter("rows"));   //获取要显示的数据
		String sortedObject = request.getParameter("sidx");                   //根据什么查询
		String sortedValue = request.getParameter("sord");                    //以升序还是降序的方式排序
		String filters = request.getParameter("filters");                     //过滤。(不知道干嘛)

        Role role = new Role();                                               //创建一个新的role对象

        if (StringUtils.isNotBlank(filters)) {                                //判断一个字符串是不为空，空就返回false，不为空就返回true
			JSONObject jsonObject = JSONObject.fromObject(filters);
			JSONArray jsonArray = (JSONArray) jsonObject.get("rules");
			for (int i = 0; i < jsonArray.size(); i++) {
				JSONObject result = (JSONObject) jsonArray.get(i);
				if (result.getString("field").equals("roleKey") && result.getString("op").equals("eq")) {
					role.set$eq_roleKey(result.getString("data"));
				}
				if (result.getString("field").equals("roleValue") && result.getString("op").equals("cn")) {
					role.set$like_roleValue(result.getString("data"));
				}
			}
			if (((String) jsonObject.get("groupOp")).equalsIgnoreCase("OR")) {
				role.setFlag("OR");
			} else {
				role.setFlag("AND");
			}
		}
		role.setFirstResult((firstResult - 1) * maxResults);                         //设置开始的位置。
		role.setMaxResults(maxResults);                                              //设置最大。

        Map<String, String> sortedCondition = new HashMap<String, String>();
		sortedCondition.put(sortedObject, sortedValue);                              //根据id的asc升序，查询。
		role.setSortedConditions(sortedCondition);                                   //设置查询条件。

        QueryResult<Role> queryResult = roleService.doPaginationQuery(role);         //根据各种查询条件返回分页列表，传入的是一个对象，实体类

        JqGridPageView<Role> roleListView = new JqGridPageView<Role>();              //将查询结果 保存在JqGridPageView，方便前端的jqgrid获取
		roleListView.setMaxResults(maxResults);
		roleListView.setRows(queryResult.getResultList());
		roleListView.setRecords(queryResult.getTotalCount());

        writeJSON(response, roleListView);
	}

	// 2.保存角色的实体Bean
	@RequestMapping(value = "/saveRole", method = { RequestMethod.POST, RequestMethod.GET })
	public void doSave(Role entity, HttpServletRequest request, HttpServletResponse response) throws IOException {
		ExtJSBaseParameter parameter = ((ExtJSBaseParameter) entity);
		if (CMD_EDIT.equals(parameter.getCmd())) {
			roleService.merge(entity);
		} else if (CMD_NEW.equals(parameter.getCmd())) {
			roleService.persist(entity);
		}
		parameter.setSuccess(true);
		writeJSON(response, parameter);
	}

	// 3.操作角色的删除、导出Excel、字段判断和保存
	@RequestMapping(value = "/operateRole", method = { RequestMethod.POST, RequestMethod.GET })
	public void operateRole(HttpServletRequest request, HttpServletResponse response) throws Exception {
		String oper = request.getParameter("oper");
		String id = request.getParameter("id");
		if (oper.equals("del")) {
			String[] ids = id.split(",");
			deleteRole(request, response, (Long[]) ConvertUtils.convert(ids, Long.class));
		} else if (oper.equals("excel")) {
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
		} else {
			Map<String, Object> result = new HashMap<String, Object>();
			String roleKey = request.getParameter("roleKey");
			String roleValue = request.getParameter("roleValue");
			String description = request.getParameter("description");
			Role role = null;
			if (oper.equals("edit")) {
				role = roleService.get(Long.valueOf(id));
			}
			Role roleKeyRole = roleService.getByProerties("roleKey", roleKey);
			if (StringUtils.isBlank(roleKey) || StringUtils.isBlank(roleValue)) {
				response.setStatus(HttpServletResponse.SC_LENGTH_REQUIRED);
				result.put("message", "请填写角色编码和角色名称");
				writeJSON(response, result);
			} else if (null != roleKeyRole && oper.equals("add")) {
				response.setStatus(HttpServletResponse.SC_CONFLICT);
				result.put("message", "此角色编码已存在，请重新输入");
				writeJSON(response, result);
			} else if (null != roleKeyRole && !role.getRoleKey().equalsIgnoreCase(roleKey) && oper.equals("edit")) {
				response.setStatus(HttpServletResponse.SC_CONFLICT);
				result.put("message", "此角色编码已存在，请重新输入");
				writeJSON(response, result);
			} else {
				Role entity = new Role();
				entity.setRoleKey(roleKey);
				entity.setRoleValue(roleValue);
				entity.setDescription(description);
				if (oper.equals("edit")) {
					entity.setId(Long.valueOf(id));
					entity.setCmd("edit");
					entity.setPermissions(role.getPermissions());
					doSave(entity, request, response);
				} else if (oper.equals("add")) {
					entity.setCmd("new");
					// Set<String> permissions = new HashSet<String>();
					// permissions.add(roleKey + ":*");
					// entity.setPermissions(permissions);
					doSave(entity, request, response);
				}
			}
		}
	}

	// 4.删除角色
	@RequestMapping("/deleteRole")
	public void deleteRole(HttpServletRequest request, HttpServletResponse response, @RequestParam("ids") Long[] ids) throws IOException {
		boolean flag = false;
		for (int i = 0; i < ids.length; i++) {
			Long id = ids[i];
			roleService.deleteSysUserAndRoleByRoleId(id);
			flag = roleService.deleteByPK(id);
		}
		if (flag) {
			writeJSON(response, "{success:true}");
		} else {
			writeJSON(response, "{success:false}");
		}
	}

	// 5.获取角色的下拉框
	@RequestMapping(value = "/getRoleSelectList", method = { RequestMethod.POST, RequestMethod.GET })
	public void getRoleSelectList(HttpServletRequest request, HttpServletResponse response) throws Exception {
		List<Role> roleList = roleService.doQueryAll();
		StringBuilder builder = new StringBuilder();
		builder.append("<select>");
		for (int i = 0; i < roleList.size(); i++) {
			builder.append("<option value='" + roleList.get(i).getRoleKey() + "'>" + roleList.get(i).getRoleValue() + "</option>");
		}
		builder.append("</select>");
		writeJSON(response, builder.toString());
	}

}
