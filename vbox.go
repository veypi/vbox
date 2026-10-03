// Package vbox 原生子进程沙箱库：规则模型 + 纯判定 + OS 落地（Seatbelt/bwrap/
// 受限令牌）+ 进程生命周期。不知道 shell、审批、grant 持久化——配置解析与
// grant 生命周期在调用方（aic-pod libs/host），每次调用编译快照传入。
//
// 规则语义（2026-09-23 用户拍板；契约见 aic/docs/permission_rules.md）：单一有序表，
// 从前向后扫、首命中生效；新规则一律插表头。行为完全由行序决定，无"谁压谁"
// 的特殊规则；审批策略属产品层，不进本包。
//
// 与 aic-pod fsauth/netauth 的关系：本包是其纯 matcher 的 first-wins 重写
// （语义反转：last-wins → first-wins），状态层（cfg 耦合/Reconcile/tempTables/
// 持久化）与默认策略源（defaultDenyPaths/CacheRoots）留在 pod。
package vbox

// Effect 规则行效果。
type Effect uint8

const (
	EffDeny Effect = iota // 读写双拒
	EffRO                 // 读放写拒
	EffRW                 // 读写
)

func (e Effect) String() string {
	switch e {
	case EffDeny:
		return "deny"
	case EffRO:
		return "ro"
	case EffRW:
		return "rw"
	}
	return ""
}

// ParseEffect 解析效果词（deny/ro/rw），非法返回 ok=false。
func ParseEffect(s string) (Effect, bool) {
	switch s {
	case "deny":
		return EffDeny, true
	case "ro":
		return EffRO, true
	case "rw":
		return EffRW, true
	}
	return EffDeny, false
}

// Class 规则行类别——仅参与调用方的行序拼接（§9.10：temp → cfg/permanent →
// builtin deny → 便利根），判定时不看。
type Class uint8

const (
	ClassTemp        Class = iota // session grant（构建时插表头）
	ClassCfg                      // cfg / permanent
	ClassBuiltin                  // 出厂内建（deny 表）
	ClassConvenience              // 便利根（workspace / 会话目录等）
)

func (c Class) String() string {
	switch c {
	case ClassTemp:
		return "temp"
	case ClassCfg:
		return "cfg"
	case ClassBuiltin:
		return "builtin"
	case ClassConvenience:
		return "convenience"
	}
	return ""
}

// Rule 规则行。Pattern：段内 *（任意非分隔符字符）、跨层 **（零或多段）、
// ?（单字符）；裸路径（无通配符）覆盖子树。Class 判定时不看。
type Rule struct {
	Pattern string
	Effect  Effect
	Class   Class
}

// FileOp 文件操作类别。
type FileOp uint8

const (
	OpRead  FileOp = iota
	OpWrite        // 含创建/修改/删除/重命名/追加——unlink/rename 判定走 MatchNoFollow
)

// Decision 判定结果。
type Decision struct {
	Allow   bool   // 本操作是否放行
	Matched int    // 命中行序号（0 起）；-1 = 未命中（兜底生效）
	Effect  Effect // 生效效果（命中行效果或兜底）
}

// FSRuleSet 文件规则集：有序表，从头扫、首命中生效。
type FSRuleSet struct {
	Rules        []Rule // 有序：从头扫、首命中生效；新规则插表头（同类插同类段头）
	DefaultWrite Effect // 未命中写兜底（EffDeny | EffRW = fs_policy）；读默认开放
}

// NewFSRuleSet 构造规则集并对每行模式做 CanonicalPattern 归一（符号链接前缀
// 展开）。直接字面构造结构体时模式必须自行保证 canonical——查询路径在 Match
// 入口被 canonical 化，模式若不是 canonical，在 macOS /home（firmlink）、/tmp
// 等 symlink 前缀下两侧错位（规则形同虚设）。grant/cfg 来源的行经
// CompileFSRule 编译已含此归一；程序化构造的表请用本函数。
func NewFSRuleSet(rules []Rule, defaultWrite Effect) FSRuleSet {
	out := FSRuleSet{Rules: make([]Rule, len(rules)), DefaultWrite: defaultWrite}
	for i, r := range rules {
		r.Pattern = CanonicalPattern(r.Pattern)
		out.Rules[i] = r
	}
	return out
}

// Match 判定 canonical 化后的 path 上 op 是否放行（跟随末段符号链接——
// open/connect 语义）。
func (s FSRuleSet) Match(path string, op FileOp) Decision {
	return s.MatchPath(Canonical(path), op)
}

// MatchNoFollow 是 unlink/rename 语义的判定入口：末段符号链接不跟随（rm/mv
// 作用于链接本身，不触达目标），父链展开、规则表判定不变。rm/mv 类操作必须
// 走此入口——否则可写根内的外向链接会被无关目标路径的策略拒掉
// （2026-09-22 实测 .venv 删除被阻的修复，迁移不得丢）。
func (s FSRuleSet) MatchNoFollow(path string, op FileOp) Decision {
	return s.MatchPath(CanonicalNoFollow(path), op)
}

// MatchPath evaluates an already normalized path without consulting the host filesystem.
func (s FSRuleSet) MatchPath(cpath string, op FileOp) Decision {
	for i, r := range s.Rules {
		if MatchPattern(r.Pattern, cpath) {
			return Decision{Allow: effectAllows(r.Effect, op), Matched: i, Effect: r.Effect}
		}
	}
	// 未命中：读默认开放；写走 DefaultWrite 兜底（EffDeny|EffRW）。
	if op == OpRead {
		return Decision{Allow: true, Matched: -1, Effect: EffRO}
	}
	return Decision{Allow: s.DefaultWrite == EffRW, Matched: -1, Effect: s.DefaultWrite}
}

func effectAllows(e Effect, op FileOp) bool {
	switch e {
	case EffRW:
		return true
	case EffRO:
		return op == OpRead
	default: // EffDeny
		return false
	}
}

// Resolve 返回路径的表判定（诊断/ explain 用）：命中行序号与效果。
func (s FSRuleSet) Resolve(path string) Decision {
	return s.MatchPath(Canonical(path), OpRead)
}
