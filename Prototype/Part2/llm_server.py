#!/usr/bin/env python3
"""
CS112 Final Project Part 2 - LLM-Enhanced Proxy Server
Flask server that provides HTML enhancement and code upload detection
"""

import os
import re
from pathlib import Path
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from bs4 import BeautifulSoup
from openai import OpenAI
from dotenv import load_dotenv

# Load environment variables from .env file
env_path = Path(__file__).parent / '.env'
if env_path.exists():
    load_dotenv(env_path)
    print(f"Loaded environment variables from {env_path}")
else:
    print("No .env file found, using system environment variables")

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes (allow JavaScript fetch from pages)

# ============================================================
# GLOBAL CONFIGURATION - API USAGE LIMITS
# ============================================================
# Set these to True to enable limits (save API quota)
# Set to False to disable limits (unlimited API usage)
# ============================================================

# Ad Detection Limits
ENABLE_AD_DETECTION_LIMIT = False  # False = Check ALL images/iframes (no limit)
MAX_IMAGES_TO_CHECK = 999999       # Effectively unlimited (used only if limit enabled)
MAX_IFRAMES_TO_CHECK = 999999      # Effectively unlimited (used only if limit enabled)

# Summary Generation Limits
ENABLE_SUMMARY_LENGTH_LIMIT = False  # False = Use full page content (no limit)
MAX_SUMMARY_INPUT_LENGTH = 999999    # Effectively unlimited (used only if limit enabled)
MAX_SUMMARY_OUTPUT_TOKENS = 2000     # LLM output limit (reasonable max, not a restriction)

# Code Detection Limits
ENABLE_CODE_DETECTION_LIMIT = False  # False = Analyze full POST body (no limit)
MAX_CODE_INPUT_LENGTH = 999999       # Effectively unlimited (used only if limit enabled)
CODE_LINE_THRESHOLD = 200            # Business logic: 200 lines triggers warning

# LLM API Parameters (Optimal values, not restrictions)
LLM_TEMPERATURE_SUMMARY = 0.7        # Summary: balanced creativity
LLM_TEMPERATURE_AD_DETECT = 0.3      # Ad detection: strict and consistent
LLM_TEMPERATURE_CODE_DETECT = 0.2    # Code detection: very strict

# Performance Optimization
ENABLE_DEBUG_LOGGING = True          # Show detailed logs for monitoring

# ============================================================
# CURRENT CONFIGURATION: ALL LIMITS DISABLED
# - Ad detection: ALL images and iframes will be checked by LLM
# - Summary: FULL page content will be analyzed
# - Code detection: FULL POST body will be analyzed
# ============================================================

# DeepSeek API configuration
DEEPSEEK_API_KEY = os.environ.get('DEEPSEEK_API_KEY', '')
DEEPSEEK_BASE_URL = "https://api.deepseek.com"

# Initialize DeepSeek client
client = None
if DEEPSEEK_API_KEY:
    client = OpenAI(api_key=DEEPSEEK_API_KEY, base_url=DEEPSEEK_BASE_URL)

# Flask server configuration
FLASK_HOST = os.environ.get('FLASK_HOST', '127.0.0.1')
FLASK_PORT = int(os.environ.get('FLASK_PORT', '5000'))

# Print configuration on startup
print("=" * 60)
print("LLM Proxy Configuration:")
print("=" * 60)
print(f"API Limits Enabled:")
print(f"  - Ad Detection Limit: {ENABLE_AD_DETECTION_LIMIT}")
print(f"    (Max Images: {MAX_IMAGES_TO_CHECK}, Max Iframes: {MAX_IFRAMES_TO_CHECK})")
print(f"  - Summary Length Limit: {ENABLE_SUMMARY_LENGTH_LIMIT}")
print(f"    (Max Input: {MAX_SUMMARY_INPUT_LENGTH} chars)")
print(f"  - Code Detection Limit: {ENABLE_CODE_DETECTION_LIMIT}")
print(f"    (Max Input: {MAX_CODE_INPUT_LENGTH} chars)")
print(f"Code Detection Threshold: {CODE_LINE_THRESHOLD} lines")
print(f"Debug Logging: {ENABLE_DEBUG_LOGGING}")
print("=" * 60)


@app.route('/api/summary', methods=['GET', 'POST'])
def get_summary():
    """
    Generate AI summary for a given URL
    Called by JavaScript injected into the page
    
    Query parameters (GET):
        url: The page URL
        content: Optional page text content (first 5000 chars)
    
    JSON body (POST):
        url: The page URL
        content: Page text content
    
    Returns:
    {
        "summary": "AI generated summary text"
    }
    """
    try:
        # 支持GET和POST两种方式
        if request.method == 'POST':
            data = request.get_json()
            page_url = data.get('url', '')
            page_content = data.get('content', '')
        else:
            page_url = request.args.get('url', '')
            page_content = request.args.get('content', '')
        
        if ENABLE_DEBUG_LOGGING:
            print("")
            print("🤖" + "=" * 58 + "🤖")
            print("📋 JavaScript异步请求摘要")
            print("=" * 60)
            print(f"   网址：{page_url[:70] if page_url else '(无)'}")
            print(f"   内容长度：{len(page_content)} 字符")
            print("   准备调用DeepSeek API...")
            print("=" * 60)
        
        if not page_content or len(page_content) < 50:
            if ENABLE_DEBUG_LOGGING:
                print("⚠️  内容太少，返回默认消息")
            return jsonify({'summary': '页面内容不足，无法生成摘要。'})
        
        # Generate summary using LLM (简化版，只提取文本总结)
        summary = generate_ai_summary_from_text_fast(page_content)
        
        if ENABLE_DEBUG_LOGGING:
            print("")
            print("📋 LLM摘要生成完成")
            print("=" * 60)
            print(f"✅ 摘要已生成并返回给浏览器")
            print(f"   摘要长度：{len(summary)} 字符")
            print(f"   摘要内容：{summary[:100]}...")
            print("🤖" + "=" * 58 + "🤖")
            print("")
        
        return jsonify({
            'summary': summary,
            'url': page_url
        })
    
    except Exception as e:
        if ENABLE_DEBUG_LOGGING:
            print("")
            print("❌ 摘要生成失败")
            print(f"   错误: {e}")
            print("🤖" + "=" * 58 + "🤖")
            print("")
        return jsonify({'error': str(e), 'summary': '摘要生成失败'}), 200  # 返回200避免前端报错


@app.route('/enhance', methods=['POST'])
def enhance_html():
    """
    快速注入JavaScript脚本，异步加载AI摘要（不阻塞页面加载）
    """
    try:
        # Get JSON data
        data = request.get_json(force=True)
        
        if not data:
            return jsonify({'error': 'Invalid JSON'}), 400
        
        # Check if HTML is base64 encoded (new method)
        if 'html_base64' in data:
            import base64
            html_content = base64.b64decode(data['html_base64']).decode('utf-8', errors='replace')
            original_url = data.get('url', '')
            if ENABLE_DEBUG_LOGGING:
                print(f"[ENHANCE] 收到HTML：{len(html_content)} 字节, URL: {original_url}")
        # Fallback: regular HTML (old method)
        elif 'html' in data:
            html_content = data['html']
            original_url = data.get('url', '')
        else:
            return jsonify({'error': 'Missing html or html_base64 in request'}), 400
        
        # ===== 快速方案：只注入JavaScript，不等待LLM =====
        # 立即返回注入了JS的HTML，JavaScript会异步调用/api/summary
        modified_html = inject_async_summary_script(html_content, original_url)
        
        if ENABLE_DEBUG_LOGGING:
            print(f"[ENHANCE] ✅ 快速返回HTML ({len(modified_html)} 字节), JS将异步加载摘要")
        
        # 使用base64编码传输（避免Unicode问题）
        import base64
        html_base64 = base64.b64encode(modified_html.encode('utf-8')).decode('ascii')
        
        # 返回简单的JSON（只包含base64）
        import json
        response_json = json.dumps({'html_base64': html_base64}, ensure_ascii=True)
        
        from flask import Response
        return Response(response_json, mimetype='application/json')
    
    except Exception as e:
        if ENABLE_DEBUG_LOGGING:
            print(f"[ERROR] 网页处理失败: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/check_upload', methods=['POST'])
def check_upload():
    """
    [TEMPORARILY DISABLED]
    Check if POST request contains code (200+ lines)
    
    To enable: uncomment the code detection logic below
    """
    try:
        data = request.get_json()
        if not data or 'body' not in data:
            return jsonify({'error': 'Missing body in request'}), 400
        
        # FEATURE TEMPORARILY DISABLED
        # Return false by default (no code detected)
        return jsonify({
            'is_code': False,
            'code_lines': 0
        })
        
        # EXAMPLE CODE - Uncomment to enable code detection:
        """
        body = data['body']
        
        # Check if body contains code
        is_code, code_lines = detect_code_in_text(body)
        
        if ENABLE_DEBUG_LOGGING:
            print(f"[LLM] Code check result: is_code={is_code}, lines={code_lines}, threshold={CODE_LINE_THRESHOLD}")
        
        if is_code and code_lines >= CODE_LINE_THRESHOLD:
            # Return warning page
            warning_html = generate_warning_page()
            return jsonify({
                'is_code': True,
                'code_lines': code_lines,
                'warning_html': warning_html
            })
        else:
            return jsonify({
                'is_code': False,
                'code_lines': code_lines
            })
        """
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/static/ads.png', methods=['GET'])
def serve_ad_image():
    """Serve the ads.png replacement image"""
    try:
        return send_file('ads.png', mimetype='image/png')
    except Exception as e:
        return str(e), 404


def generate_ai_summary_from_text_fast(text):
    """
    快速生成AI摘要（用于异步JavaScript调用）
    
    Args:
        text: Plain text string
    
    Returns:
        summary text
    """
    if not client:
        return "⚠️ DeepSeek API未配置，无法生成摘要。"
    
    try:
        # 限制输入长度（加快速度）
        text = text[:2000]
        
        if ENABLE_DEBUG_LOGGING:
            print(f"[LLM] 生成摘要中... (输入：{len(text)} 字符)")
        
        import time
        start_time = time.time()
        
        # 调用LLM（简化prompt，加快速度）
        response = client.chat.completions.create(
            model="deepseek-chat",
            messages=[
                {"role": "system", "content": "你是网页摘要助手。用中文，70字以内。"},
                {"role": "user", "content": f"总结这个网页：\n{text}"}
            ],
            temperature=0.7,
            max_tokens=200
        )
        
        elapsed = time.time() - start_time
        summary = response.choices[0].message.content
        
        if ENABLE_DEBUG_LOGGING:
            print(f"[LLM] ✅ 摘要生成完成 (耗时: {elapsed:.2f}秒, 长度: {len(summary)} 字符)")
        
        return summary
        
    except Exception as e:
        if ENABLE_DEBUG_LOGGING:
            print(f"[LLM] ❌ 摘要生成失败: {e}")
        return "❌ 摘要生成失败，请稍后重试。"


def generate_ai_summary_from_text(text):
    """
    Use LLM to generate summary from plain text
    
    Args:
        text: Plain text string
    
    Returns:
        summary text
    """
    if not client:
        print("")
        print("=" * 60)
        print("⚠️  LLM未配置！")
        print("=" * 60)
        print("DEEPSEEK_API_KEY未设置，请检查.env文件")
        print("=" * 60)
        return "LLM未配置，请设置DEEPSEEK_API_KEY"
    
    try:
        # Apply length limit if enabled
        original_length = len(text)
        if ENABLE_SUMMARY_LENGTH_LIMIT:
            text = text[:MAX_SUMMARY_INPUT_LENGTH]
            print(f"   文本长度限制：{original_length} → {len(text)} 字符")
        
        print("")
        print("📋 步骤4：LLM返回的结果")
        print("=" * 60)
        print(f"   正在调用DeepSeek API生成摘要...")
        print(f"   输入文本长度：{len(text)} 字符")
        print(f"   温度参数：{LLM_TEMPERATURE_SUMMARY}")
        print(f"   最大输出：{MAX_SUMMARY_OUTPUT_TOKENS} tokens")
        print("   ⏳ 请稍候...")
        
        import time
        start_time = time.time()
        
        # Call DeepSeek API
        response = client.chat.completions.create(
            model="deepseek-chat",
            messages=[
                {"role": "system", "content": "You are a helpful assistant that summarizes web pages concisely in English. Keep summaries under 150 words."},
                {"role": "user", "content": f"Please summarize the main content of this webpage:\n\n{text}"}
            ],
            temperature=LLM_TEMPERATURE_SUMMARY,
            max_tokens=MAX_SUMMARY_OUTPUT_TOKENS
        )
        
        elapsed = time.time() - start_time
        summary = response.choices[0].message.content
        
        print("")
        print("   ✅ LLM响应成功接收！")
        print(f"   ⏱️  API调用耗时：{elapsed:.2f} 秒")
        print(f"   📊 摘要长度：{len(summary)} 字符")
        print("")
        print("   📄 LLM返回的摘要内容：")
        print("   " + "-" * 56)
        # 显示完整摘要，每行缩进
        for line in summary.split('\n'):
            print(f"   {line}")
        print("   " + "-" * 56)
        print("=" * 60)
        
        return summary
        
    except Exception as e:
        print("")
        print("   ❌ DeepSeek API调用失败！")
        print(f"   错误信息：{e}")
        print("=" * 60)
        return "摘要生成失败，请稍后重试"


def inject_async_summary_script(html_content, page_url):
    """
    注入轻量级JavaScript脚本，异步加载AI摘要（不阻塞页面加载）
    
    Args:
        html_content: 原始HTML
        page_url: 页面URL
    
    Returns:
        修改后的HTML（只添加了JS脚本，立即返回）
    """
    # 创建异步加载脚本
    async_script = f'''
<script>
// CS112 AI Summary - Async Loader
(function() {{
    // 等待DOM加载完成
    if (document.readyState === 'loading') {{
        document.addEventListener('DOMContentLoaded', initAISummary);
    }} else {{
        // DOM already loaded
        setTimeout(initAISummary, 100);
    }}
    
    function initAISummary() {{
        try {{
            // 1. 立即创建顶部横幅（加载状态）
            createBanner('⏳ 正在生成AI摘要...');
            
            // 2. 提取页面文本内容
            var pageText = extractPageText();
            
            // 3. 异步请求Flask生成摘要
            requestSummary(pageText);
        }} catch(e) {{
            console.error('[AI Summary] Error:', e);
        }}
    }}
    
    function createBanner(message) {{
        var banner = document.createElement('div');
        banner.id = 'cs112-ai-summary-banner';
        banner.innerHTML = `
            <div style="all: initial; display: block; width: 100%; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 0; margin: 0; box-sizing: border-box; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; position: relative; z-index: 999999;">
                <div style="max-width: 1200px; margin: 0 auto; padding: 20px; background: rgba(255, 255, 255, 0.95); box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                    <div style="display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap;">
                        <div style="flex: 1; min-width: 300px; margin-right: 20px;">
                            <h2 style="margin: 0 0 15px 0; padding: 0; font-size: 24px; font-weight: 700; color: #667eea; display: flex; align-items: center;">
                                <span style="margin-right: 10px; font-size: 28px;">🤖</span>
                                <span>AI 页面摘要</span>
                            </h2>
                            <div id="cs112-summary-content" style="background: #f8f9fa; border-left: 4px solid #667eea; padding: 15px; border-radius: 8px; margin-bottom: 10px;">
                                <p style="margin: 0; padding: 0; font-size: 16px; line-height: 1.8; color: #333;">
                                    ${{message}}
                                </p>
                            </div>
                            <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; font-size: 13px; color: #666;">
                                <span>💡 <strong>Powered by DeepSeek AI</strong> | SafeGate Proxy</span>
                                <button onclick="document.getElementById('cs112-ai-summary-banner').remove()" style="background: #e74c3c; color: white; border: none; padding: 8px 16px; border-radius: 5px; cursor: pointer; font-size: 14px; font-weight: 600; margin-top: 10px;">关闭</button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;
        
        // 插入到页面顶部
        if (document.body) {{
            document.body.insertBefore(banner, document.body.firstChild);
        }}
    }}
    
    function updateBanner(message) {{
        var content = document.getElementById('cs112-summary-content');
        if (content) {{
            content.innerHTML = '<p style="margin: 0; padding: 0; font-size: 16px; line-height: 1.8; color: #333;">' + message + '</p>';
        }}
    }}
    
    function extractPageText() {{
        // 获取页面可见文本（前3000字符）
        var text = document.body.innerText || document.body.textContent || '';
        return text.substring(0, 3000);
    }}
    
    function requestSummary(pageText) {{
        var url = 'http://127.0.0.1:5000/api/summary';
        
        // 使用POST发送数据（避免URL长度限制）
        fetch(url, {{
            method: 'POST',
            headers: {{
                'Content-Type': 'application/json'
            }},
            body: JSON.stringify({{
                url: '{page_url}',
                content: pageText
            }})
        }})
        .then(response => response.json())
        .then(data => {{
            if (data.summary) {{
                updateBanner(data.summary);
                console.log('[AI Summary] ✅ 摘要已加载');
            }} else {{
                updateBanner('❌ 摘要生成失败');
            }}
        }})
        .catch(error => {{
            console.error('[AI Summary] 请求失败:', error);
            updateBanner('⚠️ 无法连接到AI服务器');
        }});
    }}
}})();
</script>
'''
    
    # 在<body>标签后插入脚本（如果找到的话）
    body_pos = html_content.find('<body')
    if body_pos != -1:
        body_end = html_content.find('>', body_pos)
        if body_end != -1:
            before = html_content[:body_end+1]
            after = html_content[body_end+1:]
            modified = before + async_script + after
            return modified
    
    # 在<html>标签后插入
    html_pos = html_content.find('<html')
    if html_pos != -1:
        html_end = html_content.find('>', html_pos)
        if html_end != -1:
            before = html_content[:html_end+1]
            after = html_content[html_end+1:]
            modified = before + async_script + after
            return modified
    
    # 直接放在最前面
    return async_script + html_content


def generate_ai_summary_from_text_simple(html_content):
    """
    简单的LLM摘要生成函数（在Flask终端显示结果）
    无论页面大小，都会尝试生成摘要
    
    Args:
        html_content: HTML string
    
    Returns:
        summary text (never None, always returns something)
    """
    if not client:
        print("   ⚠️  DeepSeek API未配置")
        return "DeepSeek API未配置，无法生成摘要。"
    
    try:
        # Extract text and title from HTML
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Get title
        title = soup.title.string if soup.title else "未知标题"
        
        # Remove script and style elements
        for script in soup(["script", "style"]):
            script.decompose()
        
        # Get text
        text = soup.get_text()
        
        # Clean up text
        lines = (line.strip() for line in text.splitlines())
        chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
        text = ' '.join(chunk for chunk in chunks if chunk)
        
        original_len = len(text)
        
        # 如果文本太少，就总结标题和基本信息
        if original_len < 100:
            print(f"   📊 页面内容很少（{original_len} 字符）")
            print(f"   📝 页面标题：{title}")
            print(f"   📤 调用LLM总结标题和基本信息...")
            
            import time
            start_time = time.time()
            
            response = client.chat.completions.create(
                model="deepseek-chat",
                messages=[
                    {"role": "system", "content": "你是一个网页摘要助手。即使内容很少，也要生成有意义的描述。用中文，50字以内。"},
                    {"role": "user", "content": f"这个网页的标题是：{title}\n内容：{text if text else '无内容'}\n请简单描述这个页面。"}
                ],
                temperature=0.7,
                max_tokens=200
            )
            
            elapsed = time.time() - start_time
            summary = response.choices[0].message.content
            
            print(f"   ✅ LLM响应成功！耗时：{elapsed:.2f} 秒")
            print(f"   📊 摘要长度：{len(summary)} 字符")
            return summary
        
        # 正常页面，使用前3000字符
        text = text[:3000]
        
        print(f"   📊 原始文本：{original_len} 字符，发送给LLM：{len(text)} 字符")
        print(f"   📝 页面标题：{title}")
        print(f"   📤 正在调用DeepSeek API...")
        
        import time
        start_time = time.time()
        
        response = client.chat.completions.create(
            model="deepseek-chat",
            messages=[
                {"role": "system", "content": "你是一个网页摘要助手。用中文总结网页内容，控制在100字以内。"},
                {"role": "user", "content": f"网页标题：{title}\n\n网页内容：\n{text}\n\n请总结（100字以内）"}
            ],
            temperature=0.7,
            max_tokens=300
        )
        
        elapsed = time.time() - start_time
        summary = response.choices[0].message.content
        
        print(f"   ✅ LLM响应成功！耗时：{elapsed:.2f} 秒")
        print(f"   📊 摘要长度：{len(summary)} 字符")
        
        return summary
        
    except Exception as e:
        print(f"   ❌ LLM调用失败：{e}")
        # 即使失败，也返回标题信息
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            title = soup.title.string if soup.title else "页面"
            return f"LLM调用失败，这是一个名为'{title}'的网页。"
        except:
            return "页面摘要生成失败，但浮窗功能正常。"


'''
# 旧版本的异步加载函数（已弃用，使用inject_simple_widget_html替代）
def inject_fixed_summary_widget_OLD(html_content, page_url):
    """
    [DEPRECATED] Old async loading version
    
    Args:
        html_content: Original HTML
        page_url: Page URL
    
    Returns:
        Modified HTML with widget injected
    """
    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Create simple JavaScript that just shows a fixed widget
        js_code = """
        <script>
        (function() {
            console.log('');
            console.log('════════════════════════════════════════════════');
            console.log('🔧 固定浮窗测试脚本已加载');
            console.log('════════════════════════════════════════════════');
            
            // Wait for page to load
            if (document.readyState === 'loading') {{
                console.log('[AI Summary] Waiting for DOMContentLoaded...');
                document.addEventListener('DOMContentLoaded', initAISummary);
            }} else {{
                console.log('[AI Summary] DOM already loaded, initializing...');
                initAISummary();
            }}
            
            function initAISummary() {{
                console.log('');
                console.log('════════════════════════════════════════════════');
                console.log('🤖 AI SUMMARY INITIALIZATION');
                console.log('════════════════════════════════════════════════');
                
                // Step 1: Extract page text content
                console.log('');
                console.log('📋 STEP 1: Extracting page content...');
                var pageText = document.body.innerText || document.body.textContent || '';
                console.log('   ✅ Content extracted:', pageText.length, 'characters');
                
                // Skip if page is too small (likely a detection page)
                if (pageText.length < 200) {{
                    console.log('   ⚠️  Page too small (<200 chars), skipping summary');
                    console.log('════════════════════════════════════════════════');
                    return;
                }}
                
                pageText = pageText.substring(0, 5000); // Send first 5000 chars
                console.log('   📏 Will send:', pageText.length, 'characters to Flask');
                
                // Step 2: Create loading widget
                console.log('');
                console.log('📋 STEP 2: Creating AI Summary widget...');
                createSummaryWidget('Loading AI Summary...');
                console.log('   ✅ Widget created and displayed in top-right corner');
                
                // Step 3: Request summary from Flask
                console.log('');
                console.log('📋 STEP 3: Requesting summary from Flask...');
                var currentUrl = window.location.href;
                var flaskUrl = 'http://127.0.0.1:5000/api/summary?url=' + 
                              encodeURIComponent(currentUrl) + 
                              '&content=' + encodeURIComponent(pageText);
                
                console.log('   📤 Sending request to:', flaskUrl.substring(0, 80) + '...');
                console.log('   ⏳ Waiting for LLM to generate summary...');
                
                fetch(flaskUrl)
                    .then(response => {{
                        console.log('');
                        console.log('📋 STEP 4: Response received from Flask');
                        console.log('   📊 Status:', response.status);
                        if (response.status !== 200) {{
                            console.error('   ❌ Error status:', response.status);
                        }}
                        return response.json();
                    }})
                    .then(data => {{
                        console.log('');
                        console.log('📋 STEP 5: Processing summary data...');
                        console.log('   📦 Data received:', Object.keys(data));
                        
                        if (data.summary) {{
                            console.log('   ✅ Summary received:', data.summary.substring(0, 100) + '...');
                            console.log('   📏 Summary length:', data.summary.length, 'characters');
                            console.log('');
                            console.log('📋 STEP 6: Updating widget with summary...');
                            updateSummaryWidget(data.summary);
                            console.log('   ✅ Widget updated successfully!');
                            console.log('');
                            console.log('🎉 AI SUMMARY COMPLETE!');
                            console.log('   Look at the top-right corner of the page');
                        }} else {{
                            console.error('   ❌ No summary field in response');
                            console.error('   Response data:', data);
                            updateSummaryWidget('Failed to generate summary.');
                        }}
                        console.log('════════════════════════════════════════════════');
                    }})
                    .catch(error => {{
                        console.log('');
                        console.error('❌ FETCH ERROR IN STEP 4');
                        console.error('   Error:', error);
                        console.error('   This usually means Flask is not running on port 5000');
                        console.log('════════════════════════════════════════════════');
                        updateSummaryWidget('Failed to load summary. Flask server may be unavailable.');
                    }});
            }}
            
            function createSummaryWidget(initialText) {{
                var widget = document.createElement('div');
                widget.id = 'ai-summary-widget';
                widget.innerHTML = `
                    <div style="
                        position: fixed;
                        top: 80px;
                        right: 20px;
                        width: 350px;
                        max-height: 550px;
                        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                        border-radius: 12px;
                        box-shadow: 0 10px 40px rgba(0, 0, 0, 0.3);
                        z-index: 999999;
                        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                        overflow: hidden;
                        animation: slideIn 0.5s ease-out;
                    ">
                        <style>
                            @keyframes slideIn {{
                                from {{ transform: translateX(400px); opacity: 0; }}
                                to {{ transform: translateX(0); opacity: 1; }}
                            }}
                            @keyframes spin {{
                                0% {{ transform: rotate(0deg); }}
                                100% {{ transform: rotate(360deg); }}
                            }}
                        </style>
                        <div style="
                            background: rgba(255, 255, 255, 0.95);
                            padding: 15px;
                            border-radius: 12px;
                            margin: 2px;
                        ">
                            <div style="
                                display: flex;
                                justify-content: space-between;
                                align-items: center;
                                margin-bottom: 10px;
                            ">
                                <h3 style="
                                    margin: 0;
                                    font-size: 18px;
                                    font-weight: 600;
                                    color: #667eea;
                                    display: flex;
                                    align-items: center;
                                ">
                                    <span style="margin-right: 8px;">🤖</span>
                                    AI Summary
                                </h3>
                                <button onclick="this.closest('#ai-summary-widget').remove()" style="
                                    background: none;
                                    border: none;
                                    font-size: 24px;
                                    cursor: pointer;
                                    color: #999;
                                    padding: 0;
                                    line-height: 1;
                                ">×</button>
                            </div>
                            <div id="summary-content" style="
                                font-size: 14px;
                                color: #333;
                                line-height: 1.6;
                                max-height: 420px;
                                overflow-y: auto;
                            ">
                                <p style="margin: 0 0 10px 0;">
                                    <strong>📄 Page Summary:</strong>
                                </p>
                                <div id="summary-text" style="
                                    background: #f8f9fa;
                                    padding: 12px;
                                    border-radius: 8px;
                                    margin-bottom: 10px;
                                    color: #444;
                                    border-left: 3px solid #667eea;
                                    min-height: 50px;
                                ">
                                    <span style="display: inline-block; animation: spin 1s linear infinite;">⏳</span>
                                    ${{initialText}}
                                </div>
                                <div style="
                                    background: #e8f4f8;
                                    padding: 10px;
                                    border-radius: 8px;
                                    margin-top: 10px;
                                ">
                                    <p style="margin: 0; font-size: 12px; color: #666;">
                                        💡 <strong>Powered by DeepSeek AI</strong><br>
                                        Protected by SafeGate Proxy
                                    </p>
                                </div>
                            </div>
                        </div>
                    </div>
                `;
                document.body.appendChild(widget);
            }}
            
            function updateSummaryWidget(summaryText) {{
                var summaryDiv = document.getElementById('summary-text');
                if (summaryDiv) {{
                    summaryDiv.innerHTML = summaryText;
                }}
            }}
        }})();
        </script>
        """
        
        # Insert script before closing body tag
        if soup.body:
            script_tag = BeautifulSoup(js_code, 'html.parser')
            soup.body.append(script_tag)
            
            if ENABLE_DEBUG_LOGGING:
                print(f"[INJECT] JavaScript injected for async summary loading")
            
            return str(soup)
        else:
            return html_content
            
    except Exception as e:
        print(f"[ERROR] Error injecting JS: {e}")
        return html_content
'''

# ============================================================
# EXAMPLE FUNCTIONS - Ad Detection (Currently Disabled)
# ============================================================
# These functions are preserved as examples but not currently used
# To enable: modify enhance_html() to call replace_ads_in_html()
# ============================================================

def inject_ai_summary_widget_server_side(soup, summary=None):
    """
    Inject AI Summary floating widget into HTML
    
    Args:
        soup: BeautifulSoup object
        summary: AI-generated summary text
    
    Returns:
        modified soup
    """
    if not summary:
        summary = "This page has been processed by CS112 SafeGate Proxy. Ads have been replaced with safe placeholders."
    
    # Create the AI Summary widget HTML
    widget_html = f"""
    <div id="ai-summary-widget" style="
        position: fixed;
        top: 80px;
        right: 20px;
        width: 350px;
        max-height: 550px;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        border-radius: 12px;
        box-shadow: 0 10px 40px rgba(0, 0, 0, 0.3);
        z-index: 999999;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        overflow: hidden;
    ">
        <div style="
            background: rgba(255, 255, 255, 0.95);
            padding: 15px;
            border-radius: 12px;
            margin: 2px;
        ">
            <div style="
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 10px;
            ">
                <h3 style="
                    margin: 0;
                    font-size: 18px;
                    font-weight: 600;
                    color: #667eea;
                    display: flex;
                    align-items: center;
                ">
                    <span style="margin-right: 8px;">🤖</span>
                    AI Summary
                </h3>
                <button onclick="document.getElementById('ai-summary-widget').style.display='none'" style="
                    background: none;
                    border: none;
                    font-size: 24px;
                    cursor: pointer;
                    color: #999;
                    padding: 0;
                    line-height: 1;
                ">×</button>
            </div>
            <div style="
                font-size: 14px;
                color: #333;
                line-height: 1.6;
                max-height: 420px;
                overflow-y: auto;
            ">
                <p style="margin: 0 0 10px 0;">
                    <strong>📄 Page Summary:</strong>
                </p>
                <div style="
                    background: #f8f9fa;
                    padding: 12px;
                    border-radius: 8px;
                    margin-bottom: 10px;
                    color: #444;
                    border-left: 3px solid #667eea;
                ">
                    {summary}
                </div>
                <div style="
                    background: #e8f4f8;
                    padding: 10px;
                    border-radius: 8px;
                    margin-top: 10px;
                ">
                    <p style="margin: 0; font-size: 12px; color: #666;">
                        💡 <strong>Powered by DeepSeek AI</strong><br>
                        Protected by SafeGate Proxy
                    </p>
                </div>
            </div>
        </div>
    </div>
    """
    
    # Insert widget before closing body tag
    if soup.body:
        widget_tag = BeautifulSoup(widget_html, 'html.parser')
        soup.body.append(widget_tag)
    
    return soup


# ============================================================
# EXAMPLE FUNCTIONS - Ad Detection (currently disabled)
# Uncomment the block below to enable ad detection
# ============================================================
'''
def is_ad_element_llm(element_html):
    """Use LLM to determine if an HTML element is an advertisement"""
    if not client:
        # Fallback to pattern matching if LLM not available
        ad_patterns = [r'ad[_-]', r'ads[_-]', r'advert', r'banner', r'sponsor', r'doubleclick', r'adsense']
        ad_regex = re.compile('|'.join(ad_patterns), re.IGNORECASE)
        return bool(ad_regex.search(element_html))
    
    try:
        response = client.chat.completions.create(
            model="deepseek-chat",
            messages=[
                {"role": "system", "content": "You are an ad detection system. Analyze HTML elements and determine if they are advertisements. Reply with ONLY 'YES' or 'NO'."},
                {"role": "user", "content": f"Is this HTML element an advertisement?\n\n{element_html[:500]}"}
            ],
            temperature=LLM_TEMPERATURE_AD_DETECT,
            max_tokens=10
        )
        
        answer = response.choices[0].message.content.strip().upper()
        is_ad = 'YES' in answer
        
        if ENABLE_DEBUG_LOGGING and is_ad:
            print(f"[LLM] Ad detected in element")
        
        return is_ad
        
    except Exception as e:
        if ENABLE_DEBUG_LOGGING:
            print(f"[ERROR] LLM ad detection failed: {e}")
        # Fallback to pattern matching
        ad_patterns = [r'ad[_-]', r'ads[_-]', r'advert', r'banner', r'sponsor']
        ad_regex = re.compile('|'.join(ad_patterns), re.IGNORECASE)
        return bool(ad_regex.search(element_html))


def replace_ads_in_html_example(html_content):
    """Replace advertisement images and iframes with ads.png using LLM detection"""
    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        modified = False
        
        # Generate AI summary first
        if ENABLE_DEBUG_LOGGING:
            print("[LLM] Generating AI summary...")
        ai_summary = generate_ai_summary(html_content)
        
        # Replace ad images using LLM detection
        img_list = soup.find_all('img')
        total_images = len(img_list)
        
        if ENABLE_DEBUG_LOGGING:
            print(f"[CONFIG] Found {total_images} images on page")
        
        # Determine how many images to check
        if ENABLE_AD_DETECTION_LIMIT:
            images_to_check = min(total_images, MAX_IMAGES_TO_CHECK)
            if ENABLE_DEBUG_LOGGING:
                print(f"[CONFIG] Limit enabled: checking {images_to_check}/{total_images} images")
        else:
            images_to_check = total_images
            if ENABLE_DEBUG_LOGGING:
                print(f"[CONFIG] No limit: checking all {images_to_check} images")
        
        for img_idx, img in enumerate(img_list[:images_to_check]):
            # Get element HTML for analysis
            element_html = str(img)
            
            # Use LLM to detect if it's an ad
            if is_ad_element_llm(element_html):
                if ENABLE_DEBUG_LOGGING:
                    print(f"[LLM] Ad detected in image {img_idx+1}: {img.get('src', '')[:50]}")
                
                # Preserve dimensions if available
                width = img.get('width', '')
                height = img.get('height', '')
                
                # Replace with ads.png served by Flask
                img['src'] = 'http://127.0.0.1:5000/static/ads.png'
                
                # Keep dimensions
                if width:
                    img['width'] = width
                if height:
                    img['height'] = height
                
                modified = True
        
        # Replace ad iframes using LLM detection
        iframe_list = soup.find_all('iframe')
        total_iframes = len(iframe_list)
        
        if ENABLE_DEBUG_LOGGING:
            print(f"[CONFIG] Found {total_iframes} iframes on page")
        
        # Determine how many iframes to check
        if ENABLE_AD_DETECTION_LIMIT:
            iframes_to_check = min(total_iframes, MAX_IFRAMES_TO_CHECK)
            if ENABLE_DEBUG_LOGGING:
                print(f"[CONFIG] Limit enabled: checking {iframes_to_check}/{total_iframes} iframes")
        else:
            iframes_to_check = total_iframes
            if ENABLE_DEBUG_LOGGING:
                print(f"[CONFIG] No limit: checking all {iframes_to_check} iframes")
        
        for iframe_idx, iframe in enumerate(iframe_list[:iframes_to_check]):
            element_html = str(iframe)
            
            if is_ad_element_llm(element_html):
                if ENABLE_DEBUG_LOGGING:
                    print(f"[LLM] Ad detected in iframe {iframe_idx+1}: {iframe.get('src', '')[:50]}")
                
                # Replace iframe with img tag showing ads.png
                width = iframe.get('width', '300')
                height = iframe.get('height', '250')
                
                new_img = soup.new_tag('img', 
                                       src='http://127.0.0.1:5000/static/ads.png',
                                       width=width,
                                       height=height,
                                       alt='Advertisement')
                iframe.replace_with(new_img)
                modified = True
        
        # Inject AI Summary widget in the top-right corner
        soup = inject_ai_summary_widget(soup, ai_summary)
        modified = True  # Always mark as modified since we add the widget
        
        if ENABLE_DEBUG_LOGGING:
            print(f"[LLM] HTML enhancement complete (modified: {modified})")
        
        return str(soup), modified
    
    except Exception as e:
        print(f"[ERROR] Error replacing ads: {e}")
        return html_content, False


def detect_code_in_text_example(text):
    """Use LLM to detect if text contains programming code"""
    if not client:
        # Fallback to pattern matching
        code_patterns = [r'\bdef\s+\w+\s*\(', r'\bfunction\s+\w+\s*\(', r'\bvoid\s+\w+\s*\(']
        pattern_matches = sum(1 for pattern in code_patterns if re.search(pattern, text))
        lines = text.split('\n')
        return pattern_matches >= 2, len(lines)
    
    try:
        # Count lines
        lines = text.split('\n')
        total_lines = len(lines)
        
        # Apply length limit if enabled
        if ENABLE_CODE_DETECTION_LIMIT:
            text_sample = text[:MAX_CODE_INPUT_LENGTH]
            if ENABLE_DEBUG_LOGGING:
                print(f"[CONFIG] Code detection input limited to {MAX_CODE_INPUT_LENGTH} chars")
        else:
            text_sample = text  # Use full text
        
        if ENABLE_DEBUG_LOGGING:
            print(f"[LLM] Analyzing {len(text_sample)} chars ({total_lines} lines) for code detection...")
        
        # Use LLM to detect code
        response = client.chat.completions.create(
            model="deepseek-chat",
            messages=[
                {"role": "system", "content": "You are a code detection system. Analyze text and determine if it contains programming code. Reply with 'YES' if it contains code (especially if 200+ lines), or 'NO' if it's just regular text. Be strict."},
                {"role": "user", "content": f"Does this text contain programming code? Text has {total_lines} lines.\n\n{text_sample}"}
            ],
            temperature=LLM_TEMPERATURE_CODE_DETECT,
            max_tokens=20
        )
        
        answer = response.choices[0].message.content.strip().upper()
        is_code = 'YES' in answer
        
        if ENABLE_DEBUG_LOGGING:
            print(f"[LLM] Code detection result: {answer}, lines: {total_lines}")
        
        return is_code, total_lines
        
    except Exception as e:
        print(f"[ERROR] LLM code detection failed: {e}")
        # Fallback to pattern matching
        code_patterns = [r'\bdef\s+\w+\s*\(', r'\bfunction\s+\w+\s*\(', r'\bvoid\s+\w+\s*\(']
        pattern_matches = sum(1 for pattern in code_patterns if re.search(pattern, text))
        return pattern_matches >= 2, len(lines)


def generate_warning_page_example():
    """Generate HTML warning page for code upload detection (English)"""
    warning_html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WARNING - Code Upload Blocked</title>
    <style>
        body {
            font-family: 'Arial', 'Helvetica', sans-serif;
            background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%);
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            padding: 20px;
            animation: fadeIn 0.5s;
        }
        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }
        .warning-container {
            background: white;
            border-radius: 15px;
            padding: 50px;
            box-shadow: 0 15px 50px rgba(0, 0, 0, 0.4);
            max-width: 650px;
            text-align: center;
            animation: slideIn 0.5s;
        }
        @keyframes slideIn {
            from { transform: translateY(-50px); opacity: 0; }
            to { transform: translateY(0); opacity: 1; }
        }
        .warning-icon {
            font-size: 100px;
            margin-bottom: 20px;
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0%, 100% { transform: scale(1); }
            50% { transform: scale(1.1); }
        }
        h1 {
            color: #e74c3c;
            margin: 0 0 20px 0;
            font-size: 42px;
            font-weight: bold;
            text-transform: uppercase;
            letter-spacing: 2px;
        }
        .message {
            color: #333;
            font-size: 20px;
            line-height: 1.6;
            margin-bottom: 30px;
            font-weight: 500;
        }
        .policy {
            background: #fff3cd;
            border: 3px solid #e74c3c;
            border-radius: 10px;
            padding: 25px;
            margin: 25px 0;
            text-align: left;
        }
        .policy-title {
            font-weight: bold;
            color: #e74c3c;
            margin-bottom: 15px;
            font-size: 22px;
            text-transform: uppercase;
        }
        .policy ul {
            margin: 15px 0;
            padding-left: 25px;
        }
        .policy li {
            margin: 10px 0;
            font-size: 16px;
            color: #555;
        }
        .footer {
            color: #666;
            font-size: 14px;
            margin-top: 25px;
            padding-top: 20px;
            border-top: 2px solid #eee;
        }
        .blocked-text {
            background: #e74c3c;
            color: white;
            padding: 15px;
            border-radius: 8px;
            font-size: 18px;
            font-weight: bold;
            margin: 20px 0;
        }
    </style>
</head>
<body>
    <div class="warning-container">
        <div class="warning-icon">⚠️</div>
        <h1>WARNING!</h1>
        <div class="blocked-text">
            CODE UPLOAD BLOCKED
        </div>
        <div class="message">
            <p><strong>Detected attempt to upload or submit programming code (200+ lines)</strong></p>
        </div>
        <div class="policy">
            <div class="policy-title">🔒 Company Security Policy</div>
            <p>To protect intellectual property and business secrets, <strong>uploading ANY code from company computers to external websites is strictly PROHIBITED</strong>.</p>
            <ul>
                <li>✓ You may browse and read code online</li>
                <li>✗ Uploading, submitting, or sharing company code is FORBIDDEN</li>
                <li>⚠️ Policy violations may result in disciplinary action</li>
            </ul>
        </div>
        <div class="footer">
            <p>⚡ <strong>This action has been logged and reported to IT Security.</strong></p>
            <p>If you have questions, please contact the IT Department.</p>
            <p style="margin-top: 15px; font-weight: bold;">CS112 SafeGate Proxy - Data Leakage Prevention System</p>
        </div>
    </div>
</body>
</html>
    
    return warning_html
'''

# ============================================================
# End of Example Functions (above code block is commented out)
# ============================================================


if __name__ == '__main__':
    print("")
    print("🚀" + "=" * 58 + "🚀")
    print("   CS112 Part2 - LLM-Enhanced Proxy Server")
    print("🚀" + "=" * 58 + "🚀")
    print("")
    print(f"🌐 Server Address: http://{FLASK_HOST}:{FLASK_PORT}")
    print("")
    
    if not DEEPSEEK_API_KEY:
        print("❌ DeepSeek API: NOT CONFIGURED")
        print("⚠️  DEEPSEEK_API_KEY not set in environment variables")
        print("   LLM features will NOT work!")
    else:
        print("✅ DeepSeek API: CONFIGURED")
        print(f"🔑 API Key: {DEEPSEEK_API_KEY[:8]}...{DEEPSEEK_API_KEY[-4:]}")
    
    print("")
    print("📋 Active Features:")
    print("   ✅ AI Summary (Async loading via JavaScript)")
    print("   ❌ Ad Detection (Disabled - example code available)")
    print("   ❌ Code Upload Detection (Disabled - example code available)")
    print("")
    print("💡 When a page is accessed:")
    print("   1️⃣  Page displays immediately (no waiting)")
    print("   2️⃣  JavaScript requests summary in background")
    print("   3️⃣  AI Summary widget pops up when ready")
    print("")
    print("🔍 Watch this terminal to see LLM API calls in real-time!")
    print("")
    print("=" * 60)
    print("🎯 Ready! Waiting for requests...")
    print("=" * 60)
    print("")
    
    app.run(host=FLASK_HOST, port=FLASK_PORT, debug=True, threaded=True)

