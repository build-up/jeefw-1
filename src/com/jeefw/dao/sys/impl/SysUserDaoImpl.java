package com.jeefw.dao.sys.impl;

import org.hibernate.Query;
import org.springframework.stereotype.Repository;

import com.jeefw.dao.sys.SysUserDao;
import com.jeefw.model.sys.SysUser;

import core.dao.BaseDao;

/**
 * 用户的数据持久层的实现类
 *
 */
@Repository
public class SysUserDaoImpl extends BaseDao<SysUser> implements SysUserDao {

	public SysUserDaoImpl() {
		super(SysUser.class);
	}

    /**
     * 1.查询用户的角色。“超级管理员”，“普通管理员”，“普通会员”
     * @param sysUserId
     * @return
     */
	@Override
	public String getRoleValueBySysUserId(Long sysUserId) {
        //这里使用createSQLQuery，是使用原生sql查询。:sysUserId是使用了占位符，比较好的一个
        //如果使用createQuery，是使用HQL查询。
		Query query = this.getSession().createSQLQuery("select role_value from sysuser_role,role " +
                "where sysuser_role.role_id = role.id and sysuser_id = :sysUserId");
		query.setParameter("sysUserId", sysUserId);
		String roleValue = (String) query.uniqueResult() == null ? "" : (String) query.uniqueResult();
		return roleValue;
	}

}