# app/test_refactor.py
"""
测试重构后的代码
"""

def test_imports():
    """测试模块导入"""
    print("🧪 测试模块导入...")
    
    try:
        from ui.main_window import MachineLearningPEUI
        print("✅ 主窗口模块导入成功")
    except Exception as e:
        print(f"❌ 主窗口模块导入失败: {e}")
        return False
    
    try:
        from ui.progress_dialog import Worker
        print("✅ 进度对话框模块导入成功")
    except Exception as e:
        print(f"❌ 进度对话框模块导入失败: {e}")
        return False
    
    try:
        from ui.report_view import ReportManager
        print("✅ 报告视图模块导入成功")
    except Exception as e:
        print(f"❌ 报告视图模块导入失败: {e}")
        return False
    
    try:
        from ui.resources import get_ui_string, get_color
        print("✅ 资源模块导入成功")
    except Exception as e:
        print(f"❌ 资源模块导入失败: {e}")
        return False
    
    return True

def test_classes():
    """测试类实例化"""
    print("\n🧪 测试类实例化...")
    
    try:
        from ui.main_window import MachineLearningPEUI
        from ui.progress_dialog import Worker
        from ui.report_view import ReportManager
        
        # 测试ReportManager
        report_mgr = ReportManager()
        print("✅ ReportManager实例化成功")
        
        # 测试Worker
        worker = Worker("测试任务", ("参数1", "参数2"))
        print("✅ Worker实例化成功")
        
        # 注意：MachineLearningPEUI需要Qt环境，这里只测试导入
        print("✅ MachineLearningPEUI类导入成功")
        
        return True
        
    except Exception as e:
        print(f"❌ 类实例化失败: {e}")
        return False

def test_resources():
    """测试资源功能"""
    print("\n🧪 测试资源功能...")
    
    try:
        from ui.resources import get_ui_string, get_color, get_font
        
        # 测试UI字符串
        title = get_ui_string("app_title")
        print(f"✅ 获取UI字符串: {title}")
        
        # 测试颜色
        primary_color = get_color("primary")
        print(f"✅ 获取颜色: {primary_color}")
        
        # 测试字体
        title_font = get_font("title")
        print(f"✅ 获取字体: {title_font}")
        
        return True
        
    except Exception as e:
        print(f"❌ 资源功能测试失败: {e}")
        return False

def main():
    """主测试函数"""
    print("🚀 开始测试重构后的代码...")
    print("=" * 50)
    
    # 测试导入
    import_success = test_imports()
    
    # 测试类实例化
    class_success = test_classes()
    
    # 测试资源功能
    resource_success = test_resources()
    
    print("\n" + "=" * 50)
    print("📋 测试总结:")
    print(f"• 模块导入: {'✅ 成功' if import_success else '❌ 失败'}")
    print(f"• 类实例化: {'✅ 成功' if class_success else '❌ 失败'}")
    print(f"• 资源功能: {'✅ 成功' if resource_success else '❌ 失败'}")
    
    if import_success and class_success and resource_success:
        print("\n🎉 所有测试通过！重构成功！")
        return True
    else:
        print("\n⚠️ 部分测试失败，请检查上述错误信息。")
        return False

if __name__ == "__main__":
    main()
