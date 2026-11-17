// Metadata mirrors the frozen four plugin sources: manifests (package.json)
// and the shipped plugin translations. Interface text stays exactly as the
// original; the full four fixed names are the only supported manifests.
package modules

import "strings"

// Trans references an original manifest translation key resolved through the
// frozen plugin lang files; only the locales the plugins shipped exist and the
// original fallback locale applies to everything else.
type Trans struct {
	Namespace, Group, Key string
}

// pluginText copies the frozen plugin lang values verbatim; yggdrasil-api
// declares literal strings in its manifest and needs no namespace.
var pluginText = map[string]string{
	"InvitationCodes|general|title:en":                             "Registration Invitation Codes",
	"InvitationCodes|general|title:zh_CN":                          "注册邀请码",
	"InvitationCodes|general|description:en":                       "Require invitation codes for users when registering.",
	"InvitationCodes|general|description:zh_CN":                    "在管理后台生成邀请码，只有持有邀请码才可以注册成为本站用户。",
	"ParadiseCosmeticsStudio\\OAuthCore|general|title:en":          "OAuth Client Core",
	"ParadiseCosmeticsStudio\\OAuthCore|general|title:zh_CN":       "OAuth 客户端核心",
	"ParadiseCosmeticsStudio\\OAuthCore|general|description:en":    "Core plugin of OAuth client.",
	"ParadiseCosmeticsStudio\\OAuthCore|general|description:zh_CN": "OAuth 客户端核心插件",
	"ParadiseCosmeticsStudio\\Legacy|general|title:en":             "Legacy Skin Loading",
	"ParadiseCosmeticsStudio\\Legacy|general|title:zh_CN":          "传统皮肤加载方式",
	"ParadiseCosmeticsStudio\\Legacy|general|description:en":       "Provides legacy loading which is based on player name.",
	"ParadiseCosmeticsStudio\\Legacy|general|description:zh_CN":    "提供传统的皮肤加载方式，即直接访问角色名。",

	// disable-registration is an out-of-scope eligibility entry that a
	// restored plugin state can enable; its can_register rejection copy is
	// the frozen title text used for the controlled registration refusal.
	"ParadiseCosmeticsStudio\\DisableRegistration|general|title:en":    "Disable Registration",
	"ParadiseCosmeticsStudio\\DisableRegistration|general|title:zh_CN": "关闭注册功能",

	// invitation-codes contributes the registration field, its form labels
	// and the admin codes page texts; all copied verbatim from the frozen
	// plugin lang files.
	"InvitationCodes|general|code:en":                   "Invitation Code",
	"InvitationCodes|general|code:zh_CN":                "邀请码",
	"InvitationCodes|messages|empty:en":                 "Invitation code cannot be empty.",
	"InvitationCodes|messages|empty:zh_CN":              "邀请码不能为空",
	"InvitationCodes|messages|invalid:en":               "Invalid invitation code.",
	"InvitationCodes|messages|invalid:zh_CN":            "邀请码无效",
	"InvitationCodes|front-end|placeholder:en":          "Invitation Code",
	"InvitationCodes|front-end|placeholder:zh_CN":       "邀请码",
	"InvitationCodes|admin|title:en":                    "Generate Codes",
	"InvitationCodes|admin|title:zh_CN":                 "生成邀请码",
	"InvitationCodes|admin|generated_at:en":             "Generated At",
	"InvitationCodes|admin|generated_at:zh_CN":          "生成时间",
	"InvitationCodes|admin|available.title:en":          "Available Codes",
	"InvitationCodes|admin|available.title:zh_CN":       "目前可用的邀请码",
	"InvitationCodes|admin|available.empty:en":          "No available codes.",
	"InvitationCodes|admin|available.empty:zh_CN":       "没有可用的邀请码",
	"InvitationCodes|admin|available.amount:en":         "Amount",
	"InvitationCodes|admin|available.amount:zh_CN":      "数量",
	"InvitationCodes|admin|available.placeholder:en":    "Amount of invitation codes to be generated.",
	"InvitationCodes|admin|available.placeholder:zh_CN": "要生成的邀请码数量",
	"InvitationCodes|admin|used.title:en":               "Used Codes",
	"InvitationCodes|admin|used.title:zh_CN":            "已被使用的邀请码",
	"InvitationCodes|admin|used.empty:en":               "No used codes.",
	"InvitationCodes|admin|used.empty:zh_CN":            "没有已被使用的邀请码",
	"InvitationCodes|admin|used.user_id:en":             "User ID",
	"InvitationCodes|admin|used.user_id:zh_CN":          "使用者 UID",
	"InvitationCodes|admin|used.used_at:en":             "Used At",
	"InvitationCodes|admin|used.used_at:zh_CN":          "使用时间",

	// yggdrasil-api contributes the admin config/log pages and the
	// user-center launcher widget texts; all copied verbatim from the
	// frozen plugin lang files.
	"Yggdrasil|config|title:en":                                    "Yggdrasil API Configuration",
	"Yggdrasil|config|title:zh_CN":                                 "Yggdrasil API 配置",
	"Yggdrasil|config|url.label:en":                                "Yggdrasil API URL:",
	"Yggdrasil|config|url.label:zh_CN":                             "本站的 Yggdrasil API 地址：",
	"Yggdrasil|config|url.notice:en":                               "Please make sure the URL above is accessible before configuring authlib-injector.",
	"Yggdrasil|config|url.notice:zh_CN":                            "请确认以上 URL 能够正常访问后再进行 authlib-injector 的配置。",
	"Yggdrasil|config|common.title:en":                             "Common",
	"Yggdrasil|config|common.title:zh_CN":                          "常规配置",
	"Yggdrasil|config|common.ygg_uuid_algorithm.title:en":          "UUID Algorithm",
	"Yggdrasil|config|common.ygg_uuid_algorithm.title:zh_CN":       "UUID 生成算法",
	"Yggdrasil|config|common.ygg_uuid_algorithm.v3:en":             "Version 3: Keep it same with \"Offline Users\" (Recommended)",
	"Yggdrasil|config|common.ygg_uuid_algorithm.v3:zh_CN":          "Version 3: 与原盗版用户 UUID 一致（推荐）",
	"Yggdrasil|config|common.ygg_uuid_algorithm.v4:en":             "Version 4: Generate randomly (DO NOT use this if you expect it can be compatible with \"Offline Users\")",
	"Yggdrasil|config|common.ygg_uuid_algorithm.v4:zh_CN":          "Version 4: 随机生成（想要同时兼容盗版登录的不要选）",
	"Yggdrasil|config|common.ygg_uuid_algorithm.hint:en":           "Use \"Version 3\" to gather compatibility with offline servers.",
	"Yggdrasil|config|common.ygg_uuid_algorithm.hint:zh_CN":        "选择 Version 3 以获得对原盗版服务器的最佳兼容性。",
	"Yggdrasil|config|common.ygg_token_expire_1.title:en":          "Token Temporarily-expired Time",
	"Yggdrasil|config|common.ygg_token_expire_1.title:zh_CN":       "令牌暂时失效时间",
	"Yggdrasil|config|common.ygg_token_expire_2.title:en":          "Token Completely-expired Time",
	"Yggdrasil|config|common.ygg_token_expire_2.title:zh_CN":       "令牌完全失效时间",
	"Yggdrasil|config|common.ygg_token_expire_2.description:en":    "Specify the expiry time of Token \"Temporarily Invalid\" and \"Completely Invalid\" in seconds.",
	"Yggdrasil|config|common.ygg_token_expire_2.description:zh_CN": "分别指定 Token「暂时失效」与「完全失效」的过期时间，单位为秒",
	"Yggdrasil|config|common.ygg_tokens_limit.title:en":            "Tokens Amount Limitation",
	"Yggdrasil|config|common.ygg_tokens_limit.title:zh_CN":         "令牌数量限制",
	"Yggdrasil|config|common.ygg_tokens_limit.description:en":      "Limit maximum amount of tokens for each user.",
	"Yggdrasil|config|common.ygg_tokens_limit.description:zh_CN":   "限制每个用户能拥有令牌的最大数量",
	"Yggdrasil|config|common.ygg_rate_limit.title:en":              "Log-in/Log-out Rate Limit",
	"Yggdrasil|config|common.ygg_rate_limit.title:zh_CN":           "登录/登出频率限制",
	"Yggdrasil|config|common.ygg_rate_limit.hint:en":               "Time interval between two operations (ms).",
	"Yggdrasil|config|common.ygg_rate_limit.hint:zh_CN":            "两次操作之间的时间间隔（毫秒）",
	"Yggdrasil|config|common.ygg_skin_domain.title:en":             "Additional Skin Domain Names Whitelist",
	"Yggdrasil|config|common.ygg_skin_domain.title:zh_CN":          "额外皮肤白名单域名",
	"Yggdrasil|config|common.ygg_skin_domain.description:en":       "Only textures from the list here will be loaded. Split them with comma. URL of this site and current access URL are added by default.",
	"Yggdrasil|config|common.ygg_skin_domain.description:zh_CN":    "只有在此列表中的材质才能被加载。「本站地址」和「当前访问地址」已经默认添加至白名单列表，需要添加的额外白名单域名请使用半角逗号 (,) 分隔",
	"Yggdrasil|config|common.ygg_search_profile_max.title:en":      "Limit Number of Roles for Batch Query",
	"Yggdrasil|config|common.ygg_search_profile_max.title:zh_CN":   "批量查询角色数量限制",
	"Yggdrasil|config|common.ygg_search_profile_max.hint:en":       "How many roles can be queried in one request?",
	"Yggdrasil|config|common.ygg_search_profile_max.hint:zh_CN":    "一次请求中最多能查询几个角色",
	"Yggdrasil|config|common.ygg_show_config_section.title:en":     "Show \"Quick Configuartion\"",
	"Yggdrasil|config|common.ygg_show_config_section.title:zh_CN":  "显示快速配置板块",
	"Yggdrasil|config|common.ygg_show_config_section.label:en":     "Show \"Quick Configuration\" at user center.",
	"Yggdrasil|config|common.ygg_show_config_section.label:zh_CN":  "在用户中心首页显示「快速配置启动器」板块",
	"Yggdrasil|config|common.ygg_enable_ali.title:en":              "API Location Indicator",
	"Yggdrasil|config|common.ygg_enable_ali.title:zh_CN":           "API 地址指示",
	"Yggdrasil|config|common.ygg_enable_ali.label:en":              "Enable API Location Indicator (ALI).",
	"Yggdrasil|config|common.ygg_enable_ali.label:zh_CN":           "开启「API 地址指示 (ALI)」功能",
	"Yggdrasil|config|keypair.title:en":                            "Keypair",
	"Yggdrasil|config|keypair.title:zh_CN":                         "密钥对配置",
	"Yggdrasil|config|keypair.ygg_private_key.title:en":            "OpenSSL Private Key",
	"Yggdrasil|config|keypair.ygg_private_key.title:zh_CN":         "OpenSSL 私钥",
	"Yggdrasil|config|keypair.ygg_private_key.hint:en":             "PEM-format private key is required and public key will be generated automatically according to private key.",
	"Yggdrasil|config|keypair.ygg_private_key.hint:zh_CN":          "只需填写 PEM 格式的私钥即可，公钥会根据私钥自动生成。",
	"Yggdrasil|config|keypair.ygg_private_key.generate:en":         "Generate Private Key",
	"Yggdrasil|config|keypair.ygg_private_key.generate:zh_CN":      "生成私钥",
	"Yggdrasil|config|keypair.ygg_private_key.submit:en":           "Submit Private Key",
	"Yggdrasil|config|keypair.ygg_private_key.submit:zh_CN":        "保存私钥",
	"Yggdrasil|config|keypair.ygg_private_key.message:en":          "Click the button below to generate a private key.",
	"Yggdrasil|config|keypair.ygg_private_key.message:zh_CN":       "使用下方的按钮来自动生成符合格式的私钥。",
	"Yggdrasil|config|keypair.ygg_private_key.valid:en":            "Valid private key.",
	"Yggdrasil|config|keypair.ygg_private_key.valid:zh_CN":         "私钥有效。",
	"Yggdrasil|config|keypair.ygg_private_key.invalid:en":          "Invalid RSA private key. Please check and re-configure it.",
	"Yggdrasil|config|keypair.ygg_private_key.invalid:zh_CN":       "无效的私钥，请检查后重新配置。",
	"Yggdrasil|dnd|title:en":                                       "Quick Configuration for Launchers",
	"Yggdrasil|dnd|title:zh_CN":                                    "快速配置启动器",
	"Yggdrasil|dnd|url:en":                                         "Our Yggdrasil API Authentication URL: ",
	"Yggdrasil|dnd|url:zh_CN":                                      "本站的 Yggdrasil API 认证服务器地址：",
	"Yggdrasil|dnd|tip:en":                                         "Click the button below to copy API URL or drag the button to launcher, then the authentication server will be added.",
	"Yggdrasil|dnd|tip:zh_CN":                                      "点击下方按钮复制 API 地址，或者将按钮拖动至启动器的任意界面即可快速添加认证服务器。",
	"Yggdrasil|dnd|button:en":                                      "Drag This Button to Launcher",
	"Yggdrasil|dnd|button:zh_CN":                                   "将此按钮拖动至启动器",
	"Yggdrasil|dnd|guide:en":                                       "Launchers Configuration Guide",
	"Yggdrasil|dnd|guide:zh_CN":                                    "启动器配置教程",
	"Yggdrasil|log|title:en":                                       "Yggdrasil Logs",
	"Yggdrasil|log|title:zh_CN":                                    "Yggdrasil 日志",
	"Yggdrasil|log|header.action:en":                               "Action",
	"Yggdrasil|log|header.action:zh_CN":                            "动作",
	"Yggdrasil|log|header.params:en":                               "Parameters",
	"Yggdrasil|log|header.params:zh_CN":                            "附加参数",
	"Yggdrasil|log|header.time:en":                                 "Time",
	"Yggdrasil|log|header.time:zh_CN":                              "时间",
	"Yggdrasil|log|no-records:en":                                  "No records.",
	"Yggdrasil|log|no-records:zh_CN":                               "暂无记录",
	"Yggdrasil|log|actions.authenticate:en":                        "Sign In",
	"Yggdrasil|log|actions.authenticate:zh_CN":                     "登录",
	"Yggdrasil|log|actions.refresh:en":                             "Refresh Token",
	"Yggdrasil|log|actions.refresh:zh_CN":                          "刷新令牌",
	"Yggdrasil|log|actions.validate:en":                            "Validate Token",
	"Yggdrasil|log|actions.validate:zh_CN":                         "验证令牌",
	"Yggdrasil|log|actions.signout:en":                             "Sign Out",
	"Yggdrasil|log|actions.signout:zh_CN":                          "登出",
	"Yggdrasil|log|actions.invalidate:en":                          "Invalidate Token",
	"Yggdrasil|log|actions.invalidate:zh_CN":                       "吊销令牌",
	"Yggdrasil|log|actions.join:en":                                "Attempt to Join Server",
	"Yggdrasil|log|actions.join:zh_CN":                             "请求加入服务器",
	"Yggdrasil|log|actions.has_joined:en":                          "Join Server",
	"Yggdrasil|log|actions.has_joined:zh_CN":                       "进入服务器",
	"Yggdrasil|log|actions.undefined:en":                           "Unknown",
	"Yggdrasil|log|actions.undefined:zh_CN":                        "未知",
}

// Localized resolves a manifest translation for the request locale with the
// original fallback locale behaviour.
func (t *Trans) Localized(locale string) string {
	if t == nil {
		return ""
	}
	if text, ok := pluginText[t.Namespace+"|"+t.Group+"|"+t.Key+":"+locale]; ok {
		return text
	}
	return pluginText[t.Namespace+"|"+t.Group+"|"+t.Key+":en"]
}

// Message resolves one frozen plugin translation for display keys such as
// "InvitationCodes::messages.empty"; the original manifest namespace,
// colon-separated group and dot-separated key shape is kept.
func Message(key, locale string) string {
	head, tail, ok := strings.Cut(key, "::")
	if !ok {
		return ""
	}
	parts := strings.SplitN(tail, ".", 2)
	if len(parts) != 2 {
		return ""
	}
	t := Trans{Namespace: head, Group: parts[0], Key: parts[1]}
	return t.Localized(locale)
}

// Meta is the fixed, compiled declaration of one supported module.
type Meta struct {
	Name, Version      string
	Title, Description *Trans
	TitleLiteral       string
	DescriptionLiteral string
	IconFa, IconBg     string
	// Config is the original enchants.config presence; the handler belongs to
	// the module owner's package and stays 404 until it is delivered.
	Config bool
	// Readme original readme file presence.
	Readme bool
}

// fixed lists the supported modules in the display order of the original
// directory scan.
var fixed = []Meta{
	{
		Name: "invitation-codes", Version: "3.1.2",
		Title:       &Trans{Namespace: "InvitationCodes", Group: "general", Key: "title"},
		Description: &Trans{Namespace: "InvitationCodes", Group: "general", Key: "description"},
		IconFa:      "phone", IconBg: "gray-dark",
	},
	{
		Name: "legacy-api", Version: "1.1.3",
		Title:       &Trans{Namespace: "ParadiseCosmeticsStudio\\Legacy", Group: "general", Key: "title"},
		Description: &Trans{Namespace: "ParadiseCosmeticsStudio\\Legacy", Group: "general", Key: "description"},
		IconFa:      "republican", IconBg: "purple",
	},
	{
		Name: "oauth", Version: "1.0.6",
		Title:       &Trans{Namespace: "ParadiseCosmeticsStudio\\OAuthCore", Group: "general", Key: "title"},
		Description: &Trans{Namespace: "ParadiseCosmeticsStudio\\OAuthCore", Group: "general", Key: "description"},
		IconFa:      "box", IconBg: "primary",
	},
	{
		Name: "yggdrasil-api", Version: "5.2.1",
		TitleLiteral:       "Yggdrasil API",
		DescriptionLiteral: "Yggdrasil API + authlib-injector = ✨",
		IconFa:             "khanda", IconBg: "info", Config: true, Readme: true,
	},
}

// Metas returns the supported module declarations.
func Metas() []Meta { return append([]Meta(nil), fixed...) }

func meta(name string) (Meta, bool) {
	for _, m := range fixed {
		if m.Name == name {
			return m, true
		}
	}
	return Meta{}, false
}

// Translations resolves the displayed title/description for the manage page.
func (m Meta) Translations(locale string) (string, string) {
	title := m.TitleLiteral
	if title == "" {
		title = m.Title.Localized(locale)
	}
	description := m.DescriptionLiteral
	if description == "" {
		description = m.Description.Localized(locale)
	}
	return title, description
}
