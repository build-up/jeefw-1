package com.jeefw.test;

import core.util.*;
import org.apache.shiro.crypto.hash.Sha256Hash;
import org.junit.Test;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;

import javax.sql.DataSource;
import java.security.GeneralSecurityException;
import java.sql.Connection;

/**
 * Created by llsydn on 2016/9/19.
 */
public class GeneralTest {

    /**
     * 1.测试md5算法。
     */
    @Test
    public void TestMd5(){
        //String result = MD5.crypt("428527");
        String result = MD5.crypt("");
        System.out.println(result);
    }

    /**
     * 2.测试BeanFactoryAware。可以直接获取一个bean
     * 好像不太行吧。
     */
    @Test
    public void TestSpringBeanFactoryUtils() throws Exception {

        //System.out.print(object);
        //ApplicationContext act = new ClassPathXmlApplicationContext("applicationContext.xml");
        //DataSource dataSource=act.getBean(DataSource.class);
        //System.out.print(dataSource);

        Object  object = SpringBeanFactoryUtils.getBean("dataSource");
        System.out.print(object);
    }

    /**
     * 3.测试javaeeframeworkutils。
     * 用于文件名称的命名。生成不一样的文件名。因为以日期作为文件名，好像会出现重复，所以用这个用于鉴别的。
     */
    @Test
    public void TestJavaEEFrameworkUtils(){
        String result = JavaEEFrameworkUtils.getRandomString(3);
        System.out.print(result);
    }

    /**
     * 4.测试ip地址类。判断某个ip是否在一个ip段内
     * 这个工程现在还没使用到这个类。
     */
    @Test
    public void TestIpChecker(){
        boolean result = IPChecker.ipRangCheck("192.168.188.121",
                "182.168.188.1","192.168.188.254");
        System.out.println(result);
    }

    /**
     * 5.测试htmlutils类。
     *
     */
    @Test
    public void TestHtmlUtils(){
        //省略字符串,字符串，预计长度
        String result = HtmlUtils.omitString("lls xi huan ni yangdongni",10);
        System.out.println(result);

        //去除html代码
        result = HtmlUtils.htmltoText("<h1>nihao</h1> ");
        System.out.println(result);

        //去除html标签和空格,并保留预计长度
        result = HtmlUtils.removeHTML("<h1>nihao</h1>",3);
        System.out.println(result);

        //去除.FIXME 加这个过滤换行到 BR 的功能会把原始 HTML 代码搞乱
        result = HtmlUtils.replaceHtmlCode("<script>if(1){alert('1');}</script>");
        System.out.println(result);
    }

    /**
     * 6.测试HighPreciseComputor类。
     * 用于加减乘除。高精度的。
     */
    @Test
    public void TestHighPreciseComputor(){
        //加
        System.out.println(HighPreciseComputor.add(2, 12));
        //减
        System.out.println(HighPreciseComputor.sub(2, 12));
        //乘
        System.out.println(HighPreciseComputor.mul(2, 12));
        //除
        System.out.println(HighPreciseComputor.div(2, 12));
        //除，后面的3是表示需要保留的小数位数
        System.out.println(HighPreciseComputor.div(2, 12, 3));
        //需要四舍五入，后面2表示需要保留的小数位数
        System.out.println(HighPreciseComputor.round(4.545645, 2));
    }

    /**
     * 7.测试DESede类。
     * 用于加密（好像不太行的。）
     */
    @Test
    public void TestDESed() throws GeneralSecurityException {
        //1.第一个参数是密钥，第二个参数是密文或密码
        String result = DESede.decode("scretde3aaaaqqddfghjkliu","This4285");
        System.out.println(result);
    }

    /**
     * 8.测试new Sha256Hash(sysUserModel.getPassword()).toHex()
     * sha256hash加密
     */
    @Test
    public void testSha256Hash(){
        String result = new Sha256Hash("123456").toHex();
        System.out.println(result);
    }
}
