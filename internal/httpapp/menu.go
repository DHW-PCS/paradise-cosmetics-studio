package httpapp

import "strings"

type MenuItem struct {
	Title, URL, Icon string
	Active           bool
	Children         []MenuItem
}
type MenuGroup struct {
	Title string
	Items []MenuItem
}
type menuDefinition struct {
	key, path, icon string
	children        []menuDefinition
}

// Frozen config/menu.php; titles are resolved through the original translations.
var userMenu = []menuDefinition{
	{"general.dashboard", "user", "fa-tachometer-alt", nil},
	{"general.my-closet", "user/closet", "fa-star", nil},
	{"general.player-manage", "user/player", "fa-users", nil},
	{"general.my-reports", "user/reports", "fa-flag", nil},
	{"general.profile", "user/profile", "fa-user", nil},
	{"general.developer", "", "fa-code-branch", []menuDefinition{{"general.oauth-manage", "user/oauth/manage", "fa-feather-alt", nil}}},
}
var adminMenu = []menuDefinition{
	{"general.dashboard", "admin", "fa-tachometer-alt", nil},
	{"general.user-manage", "admin/users", "fa-users", nil},
	{"general.player-manage", "admin/players", "fa-gamepad", nil},
	{"general.report-manage", "admin/reports", "fa-flag", nil},
	{"general.customize", "admin/customize", "fa-paint-brush", nil},
	{"general.i18n", "admin/i18n", "fa-globe", nil},
	{"general.score-options", "admin/score", "fa-credit-card", nil},
	{"general.options", "admin/options", "fa-cog", nil},
	{"general.res-options", "admin/resource", "fa-atom", nil},
	{"general.status", "admin/status", "fa-battery-three-quarters", nil},
	{"general.plugin-manage", "admin/plugins/manage", "fa-plug", nil},
	{"general.plugin-market", "admin/plugins/market", "fa-shopping-bag", nil},
	{"general.check-update", "admin/update", "fa-arrow-up", nil},
}

func menuItems(definitions []menuDefinition, base, current string, t func(string) string) []MenuItem {
	var items []MenuItem
	for _, definition := range definitions {
		item := MenuItem{Title: t(definition.key), URL: base + "/" + definition.path, Icon: definition.icon, Active: definition.path == current, Children: menuItems(definition.children, base, current, t)}
		if definition.path == "" {
			item.URL = "#"
			for _, child := range item.Children {
				item.Active = item.Active || child.Active
			}
		}
		items = append(items, item)
	}
	return items
}
func sidebar(base, current string, admin bool, t func(string) string) []MenuGroup {
	explore := []menuDefinition{{"general.skinlib", "skinlib", "fa-archive", nil}}
	if strings.HasPrefix(current, "admin") {
		back := append([]menuDefinition{{"general.user-center", "user", "fa-user", nil}}, explore...)
		return []MenuGroup{{t("general.admin-panel"), menuItems(adminMenu, base, current, t)}, {t("general.back"), menuItems(back, base, current, t)}}
	}
	groups := []MenuGroup{{t("general.user-center"), menuItems(userMenu, base, current, t)}, {t("general.explore"), menuItems(explore, base, current, t)}}
	if admin {
		groups = append(groups, MenuGroup{t("general.manage"), menuItems([]menuDefinition{{"general.admin-panel", "admin", "fa-cog", nil}}, base, current, t)})
	}
	return groups
}
