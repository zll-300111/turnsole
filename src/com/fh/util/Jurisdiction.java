package com.fh.util;

import java.util.List;
import java.util.Map;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;

import com.fh.entity.system.Menu;

/**
 * 权限处理
 * @author:fh
*/
public class Jurisdiction {

	/**
	 * 访问权限及初始化按钮权限(控制按钮的显示)
	 * @param menuUrl  菜单路径
	 * @return
	 */
	public static boolean hasJurisdiction(String menuUrl){
		//判断是否拥有当前点击菜单的权限（内部过滤,防止通过url进入跳过菜单权限）
		/**
		 * 根据点击的菜单的xxx.do去菜单中的URL去匹配，当匹配到了此菜单，判断是否有此菜单的权限，没有的话跳转到404页面
		 * 根据按钮权限，授权按钮(当前点的菜单和角色中各按钮的权限匹对)
		 */
		//shiro管理的session
		Subject currentUser = SecurityUtils.getSubject();  
		Session session = currentUser.getSession();
		Boolean b = true;
		List<Menu> menuList = (List)session.getAttribute(Const.SESSION_allmenuList); //获取菜单列表（Const常量类中定义的属性值 ）
		//通过获取session中的常量进行遍历
		for(int i=0;i<menuList.size();i++){
			//获取Menu类中的属性
			for(int j=0;j<menuList.get(i).getSubMenu().size();j++){
				//通过定义在Const中url常量从而获区session中url并通过.do进行分离，再与hasJurisdiction 中String menuUrl进行对比
				if(menuList.get(i).getSubMenu().get(j).getMENU_URL().split(".do")[0].equals(menuUrl.split(".do")[0])){
					if(!menuList.get(i).getSubMenu().get(j).isHasMenu()){				//判断有无此菜单权限
						return false;
					}else{																//按钮判断
						//获取Const中与之对应的常量，并将属性值放到map集合中
						Map<String, String> map = (Map<String, String>)session.getAttribute(Const.SESSION_QX);//按钮权限
						map.remove("add");
						map.remove("del");
						map.remove("edit");
						map.remove("cha");
						//从session中获取MENU_ID
						String MENU_ID =  menuList.get(i).getSubMenu().get(j).getMENU_ID();
						String USERNAME = session.getAttribute(Const.SESSION_USERNAME).toString();	//获取当前登录者loginname
						Boolean isAdmin = "admin".equals(USERNAME);
						//定义一个Boolean类型的常量，并对其进行增删改查
						map.put("add", (RightsHelper.testRights(map.get("adds"), MENU_ID)) || isAdmin?"1":"0");
						map.put("del", RightsHelper.testRights(map.get("dels"), MENU_ID) || isAdmin?"1":"0");
						map.put("edit", RightsHelper.testRights(map.get("edits"), MENU_ID) || isAdmin?"1":"0");
						map.put("cha", RightsHelper.testRights(map.get("chas"), MENU_ID) || isAdmin?"1":"0");
						session.removeAttribute(Const.SESSION_QX);
						session.setAttribute(Const.SESSION_QX, map);	//重新分配按钮权限
					}
				}
			}
		}
		return true;
	}
	
	/**
	 * 按钮权限(方法中校验)
	 * @param menuUrl  菜单路径
	 * @param type  类型(add、del、edit、cha)
	 * @return
	 */
	public static boolean buttonJurisdiction(String menuUrl, String type){
		//判断是否拥有当前点击菜单的权限（内部过滤,防止通过url进入跳过菜单权限）
		/**
		 * 根据点击的菜单的xxx.do去菜单中的URL去匹配，当匹配到了此菜单，判断是否有此菜单的权限，没有的话跳转到404页面
		 * 根据按钮权限，授权按钮(当前点的菜单和角色中各按钮的权限匹对)
		 */
		//shiro管理的session
		Subject currentUser = SecurityUtils.getSubject();  
		Session session = currentUser.getSession();
		Boolean b = true;
		List<Menu> menuList = (List)session.getAttribute(Const.SESSION_allmenuList); //获取菜单列表
		
		for(int i=0;i<menuList.size();i++){
			for(int j=0;j<menuList.get(i).getSubMenu().size();j++){
				if(menuList.get(i).getSubMenu().get(j).getMENU_URL().split(".do")[0].equals(menuUrl.split(".do")[0])){
					if(!menuList.get(i).getSubMenu().get(j).isHasMenu()){				//判断有无此菜单权限
						return false;
					}else{																//按钮判断
						Map<String, String> map = (Map<String, String>)session.getAttribute(Const.SESSION_QX);//按钮权限
						String MENU_ID =  menuList.get(i).getSubMenu().get(j).getMENU_ID();
						String USERNAME = session.getAttribute(Const.SESSION_USERNAME).toString();	//获取当前登录者loginname
						Boolean isAdmin = "admin".equals(USERNAME);
						if("add".equals(type)){
							return ((RightsHelper.testRights(map.get("adds"), MENU_ID)) || isAdmin);
						}else if("del".equals(type)){
							return ((RightsHelper.testRights(map.get("dels"), MENU_ID)) || isAdmin);
						}else if("edit".equals(type)){
							return ((RightsHelper.testRights(map.get("edits"), MENU_ID)) || isAdmin);
						}else if("cha".equals(type)){
							return ((RightsHelper.testRights(map.get("chas"), MENU_ID)) || isAdmin);
						}
					}
				}
			}
		}
		return true;
	}
	
}
