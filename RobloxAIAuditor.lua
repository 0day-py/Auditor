-- ============================================================
-- ROBLOX AI SECURITY AUDITOR v1.0
-- Made by Jordan
-- Requires: Delta Executor, Groq API Key
-- ============================================================

local RunService = game:GetService("RunService")
local TweenService = game:GetService("TweenService")
local UserInputService = game:GetService("UserInputService")
local Players = game:GetService("Players")
local HttpService = game:GetService("HttpService")
local GuiService = game:GetService("GuiService")
local TextService = game:GetService("TextService")

local LocalPlayer = Players.LocalPlayer
local PlayerGui = LocalPlayer:WaitForChild("PlayerGui")
local Camera = workspace.CurrentCamera

-- ============================================================
-- CONFIG
-- ============================================================

local CONFIG = {
    GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions",
    GROQ_MODEL = "llama3-70b-8192",
    MAX_TOKENS = 2048,
    SCAN_TIMEOUT = 30,
    API_TIMEOUT = 45,
    TOAST_DURATION = 3.5,
    TWEEN_SPEED = 0.22,
    TWEEN_FAST = 0.12,
    MAX_FINDINGS_DISPLAY = 200,
    BATCH_SIZE = 15,
}

local PALETTE = {
    BG_DEEP     = Color3.fromRGB(10, 11, 15),
    BG_PANEL    = Color3.fromRGB(16, 18, 24),
    BG_CARD     = Color3.fromRGB(22, 25, 34),
    BG_HOVER    = Color3.fromRGB(28, 32, 44),
    BG_INPUT    = Color3.fromRGB(14, 16, 22),
    BORDER      = Color3.fromRGB(38, 44, 62),
    BORDER_LIT  = Color3.fromRGB(60, 72, 110),

    ACCENT      = Color3.fromRGB(99, 179, 237),
    ACCENT_DIM  = Color3.fromRGB(49, 100, 155),
    ACCENT_GLOW = Color3.fromRGB(139, 209, 255),

    CRITICAL    = Color3.fromRGB(248, 81, 73),
    HIGH        = Color3.fromRGB(255, 140, 50),
    MEDIUM      = Color3.fromRGB(255, 204, 0),
    LOW         = Color3.fromRGB(56, 211, 159),
    INFO        = Color3.fromRGB(130, 150, 200),

    TEXT_PRIMARY   = Color3.fromRGB(230, 237, 255),
    TEXT_SECONDARY = Color3.fromRGB(140, 155, 190),
    TEXT_MUTED     = Color3.fromRGB(80, 95, 130),
    TEXT_ACCENT    = Color3.fromRGB(99, 179, 237),

    SUCCESS     = Color3.fromRGB(56, 211, 159),
    WARNING     = Color3.fromRGB(255, 204, 0),
    ERROR_COL   = Color3.fromRGB(248, 81, 73),
    WHITE       = Color3.fromRGB(255, 255, 255),
    TRANSPARENT = Color3.fromRGB(0, 0, 0),
}

local SEVERITY_CONFIG = {
    CRITICAL = { color = PALETTE.CRITICAL, label = "CRITICAL", icon = "⛔", order = 1 },
    HIGH     = { color = PALETTE.HIGH,     label = "HIGH",     icon = "🔴", order = 2 },
    MEDIUM   = { color = PALETTE.MEDIUM,   label = "MEDIUM",   icon = "🟡", order = 3 },
    LOW      = { color = PALETTE.LOW,      label = "LOW",      icon = "🟢", order = 4 },
    INFO     = { color = PALETTE.INFO,     label = "INFO",     icon = "ℹ️", order = 5 },
}

-- ============================================================
-- STATE
-- ============================================================

local State = {
    apiKey          = "",
    isScanning      = false,
    scanCancelled   = false,
    findings        = {},
    scanLog         = {},
    remoteEvents    = {},
    remoteFunctions = {},
    bindableEvents  = {},
    totalScanned    = 0,
    scanStartTime   = 0,
    filterSeverity  = "ALL",
    sortMode        = "severity",
    searchQuery     = "",
    windowPos       = nil,
    windowSize      = nil,
    minimised       = false,
    activeTab       = "dashboard",
    toastQueue      = {},
    pendingRequests = 0,
}

-- ============================================================
-- UTILITY HELPERS
-- ============================================================

local Util = {}

function Util.ease(style, dir)
    return TweenInfo.new(CONFIG.TWEEN_SPEED, style or Enum.EasingStyle.Quart, dir or Enum.EasingDirection.Out)
end

function Util.easeFast(style, dir)
    return TweenInfo.new(CONFIG.TWEEN_FAST, style or Enum.EasingStyle.Quart, dir or Enum.EasingDirection.Out)
end

function Util.tween(obj, info, props)
    if not obj or not obj.Parent then return end
    local t = TweenService:Create(obj, info, props)
    t:Play()
    return t
end

function Util.clamp(v, mn, mx) return math.max(mn, math.min(mx, v)) end

function Util.lerp(a, b, t) return a + (b - a) * t end

function Util.round(n, dp)
    local f = 10 ^ (dp or 0)
    return math.floor(n * f + 0.5) / f
end

function Util.truncate(str, max)
    if #str <= max then return str end
    return str:sub(1, max - 3) .. "..."
end

function Util.getSafeInset()
    local ok, inset = pcall(function() return GuiService:GetGuiInset() end)
    if ok then return inset end
    return Vector2.new(0, 0)
end

function Util.isMobile()
    return UserInputService.TouchEnabled and not UserInputService.MouseEnabled
end

function Util.isTablet()
    local vp = Camera.ViewportSize
    local minDim = math.min(vp.X, vp.Y)
    return UserInputService.TouchEnabled and minDim >= 600
end

function Util.getViewport()
    return Camera.ViewportSize
end

function Util.jsonSafe(data)
    local ok, result = pcall(function() return HttpService:JSONEncode(data) end)
    return ok and result or nil
end

function Util.jsonParseSafe(str)
    local ok, result = pcall(function() return HttpService:JSONDecode(str) end)
    return ok and result or nil
end

function Util.formatTime(secs)
    if secs < 60 then return string.format("%.1fs", secs) end
    local m = math.floor(secs / 60)
    local s = math.floor(secs % 60)
    return string.format("%dm %ds", m, s)
end

function Util.timestamp()
    return os.date and os.date("%H:%M:%S") or "00:00:00"
end

-- ============================================================
-- UI FACTORY
-- ============================================================

local UI = {}

function UI.frame(props)
    local f = Instance.new("Frame")
    f.BackgroundColor3 = props.bg or PALETTE.BG_PANEL
    f.BackgroundTransparency = props.alpha or 0
    f.BorderSizePixel = 0
    f.Size = props.size or UDim2.new(1, 0, 1, 0)
    f.Position = props.pos or UDim2.new(0, 0, 0, 0)
    f.Name = props.name or "Frame"
    f.ZIndex = props.z or 1
    f.ClipsDescendants = props.clip ~= false and true or false
    if props.parent then f.Parent = props.parent end
    return f
end

function UI.corner(radius, parent)
    local c = Instance.new("UICorner")
    c.CornerRadius = UDim.new(0, radius or 8)
    if parent then c.Parent = parent end
    return c
end

function UI.stroke(color, thickness, parent, alpha)
    local s = Instance.new("UIStroke")
    s.Color = color or PALETTE.BORDER
    s.Thickness = thickness or 1
    s.Transparency = alpha or 0
    if parent then s.Parent = parent end
    return s
end

function UI.gradient(c0, c1, rot, parent)
    local g = Instance.new("UIGradient")
    g.Color = ColorSequence.new(c0, c1)
    g.Rotation = rot or 90
    if parent then g.Parent = parent end
    return g
end

function UI.padding(x, y, parent)
    local p = Instance.new("UIPadding")
    p.PaddingLeft   = UDim.new(0, x or 8)
    p.PaddingRight  = UDim.new(0, x or 8)
    p.PaddingTop    = UDim.new(0, y or 8)
    p.PaddingBottom = UDim.new(0, y or 8)
    if parent then p.Parent = parent end
    return p
end

function UI.list(dir, spacing, parent)
    local l = Instance.new("UIListLayout")
    l.FillDirection = dir or Enum.FillDirection.Vertical
    l.SortOrder = Enum.SortOrder.LayoutOrder
    l.Padding = UDim.new(0, spacing or 6)
    if parent then l.Parent = parent end
    return l
end

function UI.grid(cellSize, spacing, parent)
    local g = Instance.new("UIGridLayout")
    g.CellSize = cellSize or UDim2.new(0, 160, 0, 80)
    g.CellPadding = UDim2.new(0, spacing or 6, 0, spacing or 6)
    g.SortOrder = Enum.SortOrder.LayoutOrder
    if parent then g.Parent = parent end
    return g
end

function UI.sizeConstraint(min, max, parent)
    local c = Instance.new("UISizeConstraint")
    if min then c.MinSize = min end
    if max then c.MaxSize = max end
    if parent then c.Parent = parent end
    return c
end

function UI.label(props)
    local l = Instance.new("TextLabel")
    l.BackgroundTransparency = 1
    l.Text = props.text or ""
    l.TextColor3 = props.color or PALETTE.TEXT_PRIMARY
    l.TextSize = props.size or 14
    l.Font = props.font or Enum.Font.GothamMedium
    l.TextXAlignment = props.xalign or Enum.TextXAlignment.Left
    l.TextYAlignment = props.yalign or Enum.TextYAlignment.Center
    l.TextWrapped = props.wrap ~= false and true or false
    l.RichText = props.rich or false
    l.Size = props.sz or UDim2.new(1, 0, 0, 24)
    l.Position = props.pos or UDim2.new(0, 0, 0, 0)
    l.Name = props.name or "Label"
    l.ZIndex = props.z or 1
    l.TextTransparency = props.alpha or 0
    l.TextTruncate = props.truncate or Enum.TextTruncate.None
    if props.parent then l.Parent = props.parent end
    return l
end

function UI.button(props)
    local b = Instance.new("TextButton")
    b.BackgroundColor3 = props.bg or PALETTE.ACCENT_DIM
    b.BackgroundTransparency = props.bgAlpha or 0
    b.Text = props.text or ""
    b.TextColor3 = props.color or PALETTE.TEXT_PRIMARY
    b.TextSize = props.size or 14
    b.Font = props.font or Enum.Font.GothamBold
    b.BorderSizePixel = 0
    b.Size = props.sz or UDim2.new(1, 0, 0, 36)
    b.Position = props.pos or UDim2.new(0, 0, 0, 0)
    b.Name = props.name or "Button"
    b.ZIndex = props.z or 1
    b.AutoButtonColor = false
    b.Active = true
    if props.parent then b.Parent = props.parent end
    return b
end

function UI.input(props)
    local b = Instance.new("TextBox")
    b.BackgroundColor3 = props.bg or PALETTE.BG_INPUT
    b.Text = props.text or ""
    b.TextColor3 = props.color or PALETTE.TEXT_PRIMARY
    b.PlaceholderText = props.placeholder or ""
    b.PlaceholderColor3 = props.phColor or PALETTE.TEXT_MUTED
    b.TextSize = props.size or 14
    b.Font = props.font or Enum.Font.GothamMedium
    b.BorderSizePixel = 0
    b.ClearTextOnFocus = props.clearOnFocus ~= nil and props.clearOnFocus or false
    b.TextXAlignment = props.xalign or Enum.TextXAlignment.Left
    b.Size = props.sz or UDim2.new(1, 0, 0, 36)
    b.Position = props.pos or UDim2.new(0, 0, 0, 0)
    b.Name = props.name or "Input"
    b.ZIndex = props.z or 1
    if props.parent then b.Parent = props.parent end
    return b
end

function UI.scroll(props)
    local s = Instance.new("ScrollingFrame")
    s.BackgroundColor3 = props.bg or PALETTE.BG_PANEL
    s.BackgroundTransparency = props.alpha or 0
    s.BorderSizePixel = 0
    s.Size = props.size or UDim2.new(1, 0, 1, 0)
    s.Position = props.pos or UDim2.new(0, 0, 0, 0)
    s.ScrollBarThickness = props.barSize or 4
    s.ScrollBarImageColor3 = props.barColor or PALETTE.ACCENT_DIM
    s.CanvasSize = props.canvas or UDim2.new(0, 0, 0, 0)
    s.AutomaticCanvasSize = props.autoCanvas or Enum.AutomaticSize.Y
    s.ScrollingDirection = props.dir or Enum.ScrollingDirection.Y
    s.Name = props.name or "Scroll"
    s.ZIndex = props.z or 1
    s.ElasticBehavior = Enum.ElasticBehavior.WhenScrollable
    if props.parent then s.Parent = props.parent end
    return s
end

function UI.image(props)
    local i = Instance.new("ImageLabel")
    i.BackgroundTransparency = 1
    i.Image = props.img or ""
    i.ImageColor3 = props.color or PALETTE.WHITE
    i.ImageTransparency = props.alpha or 0
    i.Size = props.size or UDim2.new(0, 24, 0, 24)
    i.Position = props.pos or UDim2.new(0, 0, 0, 0)
    i.ScaleType = props.scale or Enum.ScaleType.Fit
    i.Name = props.name or "Image"
    i.ZIndex = props.z or 1
    if props.parent then i.Parent = props.parent end
    return i
end

-- ============================================================
-- BUTTON BEHAVIOUR (hover + press animations)
-- ============================================================

local function attachButtonBehaviour(btn, normalBg, hoverBg, pressBg, normalAlpha, hoverAlpha)
    normalAlpha = normalAlpha or 0
    hoverAlpha = hoverAlpha or 0
    normalBg = normalBg or PALETTE.BG_CARD
    hoverBg = hoverBg or PALETTE.BG_HOVER
    pressBg = pressBg or PALETTE.ACCENT_DIM

    local function setColor(col, alpha)
        if not btn or not btn.Parent then return end
        Util.tween(btn, Util.easeFast(), {
            BackgroundColor3 = col,
            BackgroundTransparency = alpha or 0
        })
    end

    local mouseIn = false

    btn.MouseEnter:Connect(function()
        mouseIn = true
        if btn.Active then
            setColor(hoverBg, hoverAlpha)
        end
    end)

    btn.MouseLeave:Connect(function()
        mouseIn = false
        setColor(normalBg, normalAlpha)
    end)

    btn.MouseButton1Down:Connect(function()
        if btn.Active then
            setColor(pressBg, 0)
            Util.tween(btn, Util.easeFast(), { Size = UDim2.new(
                btn.Size.X.Scale, btn.Size.X.Offset - 2,
                btn.Size.Y.Scale, btn.Size.Y.Offset - 2
            )})
        end
    end)

    btn.MouseButton1Up:Connect(function()
        Util.tween(btn, Util.easeFast(), { Size = UDim2.new(
            btn.Size.X.Scale, btn.Size.X.Offset + 2,
            btn.Size.Y.Scale, btn.Size.Y.Offset + 2
        )})
        if mouseIn then
            setColor(hoverBg, hoverAlpha)
        else
            setColor(normalBg, normalAlpha)
        end
    end)

    -- Touch support
    btn.TouchTap:Connect(function()
        setColor(pressBg, 0)
        task.delay(0.15, function()
            setColor(normalBg, normalAlpha)
        end)
    end)
end

-- ============================================================
-- SCANNER ENGINE
-- ============================================================

local Scanner = {}

function Scanner.collectRemotes()
    local remotes = {
        events = {},
        functions = {},
        bindables = {},
    }

    local function scanInstance(inst, depth)
        if depth > 12 then return end
        if not inst or not inst.Parent then return end

        local ok, children = pcall(function() return inst:GetChildren() end)
        if not ok then return end

        for _, child in ipairs(children) do
            if not child or not child.Parent then continue end

            local className = child.ClassName
            local name = child.Name or "Unknown"
            local path = child:GetFullName()

            if className == "RemoteEvent" then
                table.insert(remotes.events, {
                    instance  = child,
                    name      = name,
                    path      = path,
                    className = className,
                    parent    = inst.Name,
                })
            elseif className == "RemoteFunction" then
                table.insert(remotes.functions, {
                    instance  = child,
                    name      = name,
                    path      = path,
                    className = className,
                    parent    = inst.Name,
                })
            elseif className == "BindableEvent" then
                table.insert(remotes.bindables, {
                    instance  = child,
                    name      = name,
                    path      = path,
                    className = className,
                    parent    = inst.Name,
                })
            end

            scanInstance(child, depth + 1)
        end
    end

    -- Scan all game services
    local targets = {
        game:GetService("ReplicatedStorage"),
        game:GetService("Workspace"),
        game:GetService("Players"),
        game:GetService("StarterPack"),
        game:GetService("StarterGui"),
        game:GetService("StarterPlayer"),
    }

    -- Also try ReplicatedFirst
    pcall(function()
        table.insert(targets, game:GetService("ReplicatedFirst"))
    end)

    for _, svc in ipairs(targets) do
        pcall(function() scanInstance(svc, 0) end)
    end

    return remotes
end

function Scanner.buildAuditPrompt(remotes)
    -- Hard cap: too many remotes bloat the prompt past model limits.
    -- Prioritise events and functions (higher security surface) over bindables.
    local MAX_EVENTS    = 80
    local MAX_FUNCTIONS = 40
    local MAX_BINDABLES = 20

    local lines = {
        "You are an expert Roblox security auditor.",
        "Analyze the remote instances below and return ONLY a raw JSON object — no markdown, no code fences.",
        "",
        "Check for: unvalidated RemoteEvents, unsafe client-trusted arguments, sensitive operations exposed",
        "to clients (admin/economy/inventory/datastores), missing rate limits, god mode/fly/speed/teleport",
        "vectors, information leakage, privilege escalation, dangerous RemoteFunction return spoofing,",
        "anti-cheat bypasses, and DataStore manipulation risks.",
        "",
        'JSON format (respond with this exact structure): {"findings":[{"remote":"name","path":"full.path","type":"RemoteEvent","severity":"CRITICAL|HIGH|MEDIUM|LOW|INFO","category":"category","title":"short title","description":"detail","recommendation":"fix"}]}',
        "",
    }

    local function addSection(label, list, cap)
        if #list == 0 then return end
        table.insert(lines, label .. " (" .. #list .. " total" .. (#list > cap and ", showing first " .. cap or "") .. "):")
        for i = 1, math.min(#list, cap) do
            local r = list[i]
            table.insert(lines, string.format("  %d. %s | path: %s | parent: %s", i, r.name, r.path, r.parent))
        end
    end

    addSection("RemoteEvents",    remotes.events,    MAX_EVENTS)
    addSection("RemoteFunctions", remotes.functions, MAX_FUNCTIONS)
    addSection("BindableEvents",  remotes.bindables, MAX_BINDABLES)

    table.insert(lines, "\nReturn JSON findings array now:")

    local prompt = table.concat(lines, "\n")
    return prompt
end

function Scanner.callGroq(apiKey, prompt)
    if not apiKey or apiKey == "" then
        return nil, "No API key provided"
    end

    -- Estimate tokens: ~4 chars per token. llama3-70b context = 8192 total.
    -- Reserve 1500 for output, leaving ~6692 for input (~26768 chars).
    local MAX_PROMPT_CHARS = 26000
    if #prompt > MAX_PROMPT_CHARS then
        prompt = prompt:sub(1, MAX_PROMPT_CHARS)
            .. "\n\n[LIST TRUNCATED — analyse what is listed above and produce JSON findings]"
    end

    -- Safe output token budget: keep total well under 8192
    local estimatedInputTokens = math.ceil(#prompt / 4)
    local safeMaxTokens = math.max(512, math.min(1500, 8000 - estimatedInputTokens))

    local payload = Util.jsonSafe({
        model = CONFIG.GROQ_MODEL,
        max_tokens = safeMaxTokens,
        temperature = 0.2,
        messages = {
            {
                role = "system",
                content = "You are a Roblox security expert. Always respond with valid JSON only. No markdown, no code fences, no preamble. Output only the raw JSON object.",
            },
            {
                role = "user",
                content = prompt,
            },
        },
    })

    if not payload then
        return nil, "Failed to encode request payload"
    end

    local ok, response = pcall(function()
        return request({
            Url = CONFIG.GROQ_API_URL,
            Method = "POST",
            Headers = {
                ["Content-Type"] = "application/json",
                ["Authorization"] = "Bearer " .. apiKey,
            },
            Body = payload,
        })
    end)

    if not ok then
        return nil, "HTTP request failed: " .. tostring(response)
    end

    if not response then
        return nil, "No response received"
    end

    -- Extract Groq's own error message for non-200 responses
    local function groqErrMsg(code)
        local detail = ""
        if response.Body and response.Body ~= "" then
            local parsed = Util.jsonParseSafe(response.Body)
            if parsed and parsed.error and parsed.error.message then
                detail = ": " .. Util.truncate(parsed.error.message, 120)
            end
        end
        return "Groq API error HTTP " .. tostring(code) .. detail
    end

    if response.StatusCode == 400 then
        return nil, groqErrMsg(400)
    elseif response.StatusCode == 401 then
        return nil, "Invalid API key (401 Unauthorized) — check Settings"
    elseif response.StatusCode == 413 then
        return nil, "Prompt too large for model (413) — game has too many remotes"
    elseif response.StatusCode == 429 then
        return nil, "Rate limited by Groq (429) — wait a moment and retry"
    elseif response.StatusCode == 500 then
        return nil, "Groq server error (500) — try again shortly"
    elseif response.StatusCode ~= 200 then
        return nil, groqErrMsg(response.StatusCode)
    end

    local body = Util.jsonParseSafe(response.Body)
    if not body then
        return nil, "Failed to parse API response as JSON"
    end

    local content = body.choices
        and body.choices[1]
        and body.choices[1].message
        and body.choices[1].message.content

    if not content then
        return nil, "Unexpected API response structure"
    end

    -- Strip possible markdown code fences
    content = content:gsub("^```json%s*", ""):gsub("^```%s*", ""):gsub("```%s*$", ""):match("^%s*(.-)%s*$")

    local parsed = Util.jsonParseSafe(content)
    if not parsed then
        return nil, "AI returned invalid JSON. Raw: " .. Util.truncate(content, 200)
    end

    if not parsed.findings or type(parsed.findings) ~= "table" then
        return nil, "AI response missing 'findings' array"
    end

    return parsed.findings, nil
end

-- ============================================================
-- TOAST NOTIFICATION SYSTEM
-- ============================================================

local Toast = {}
Toast._container = nil
Toast._active = {}

function Toast.init(screenGui)
    Toast._container = UI.frame({
        bg = PALETTE.TRANSPARENT,
        alpha = 1,
        size = UDim2.new(0, 320, 1, 0),
        pos = UDim2.new(1, -328, 0, 0),
        name = "ToastContainer",
        z = 100,
        clip = false,
        parent = screenGui,
    })
    UI.list(Enum.FillDirection.Vertical, 8, Toast._container)
    UI.padding(0, 16, Toast._container)
end

function Toast.show(msg, kind, duration)
    kind = kind or "info"
    duration = duration or CONFIG.TOAST_DURATION

    local colors = {
        success = PALETTE.SUCCESS,
        error   = PALETTE.ERROR_COL,
        warning = PALETTE.WARNING,
        info    = PALETTE.ACCENT,
    }

    local icons = {
        success = "✓",
        error   = "✗",
        warning = "⚠",
        info    = "ℹ",
    }

    local col = colors[kind] or PALETTE.ACCENT
    local icon = icons[kind] or "ℹ"

    local card = UI.frame({
        bg = PALETTE.BG_CARD,
        size = UDim2.new(1, 0, 0, 52),
        name = "Toast",
        z = 100,
        clip = false,
        parent = Toast._container,
    })
    UI.corner(10, card)
    UI.stroke(col, 1, card)

    -- Coloured left bar
    local bar = UI.frame({
        bg = col,
        size = UDim2.new(0, 3, 1, 0),
        pos = UDim2.new(0, 0, 0, 0),
        name = "Bar",
        z = 101,
        parent = card,
    })
    UI.corner(10, bar)

    local iconLbl = UI.label({
        text = icon,
        color = col,
        size = 18,
        font = Enum.Font.GothamBold,
        sz = UDim2.new(0, 28, 1, 0),
        pos = UDim2.new(0, 12, 0, 0),
        xalign = Enum.TextXAlignment.Center,
        z = 102,
        parent = card,
    })

    local msgLbl = UI.label({
        text = msg,
        color = PALETTE.TEXT_PRIMARY,
        size = 13,
        font = Enum.Font.GothamMedium,
        sz = UDim2.new(1, -52, 1, 0),
        pos = UDim2.new(0, 44, 0, 0),
        wrap = true,
        z = 102,
        parent = card,
    })

    -- Animate in from right
    card.Position = UDim2.new(1, 20, 0, 0)
    card.BackgroundTransparency = 1
    Util.tween(card, Util.ease(Enum.EasingStyle.Back), {
        Position = UDim2.new(0, 0, 0, 0),
        BackgroundTransparency = 0,
    })

    task.delay(duration, function()
        if not card or not card.Parent then return end
        Util.tween(card, Util.ease(), {
            Position = UDim2.new(1, 20, 0, 0),
            BackgroundTransparency = 1,
        })
        task.delay(0.3, function()
            if card and card.Parent then card:Destroy() end
        end)
    end)
end

-- ============================================================
-- MODAL SYSTEM
-- ============================================================

local Modal = {}
Modal._overlay = nil
Modal._current = nil

function Modal.init(screenGui)
    Modal._overlay = UI.frame({
        bg = Color3.fromRGB(0, 0, 0),
        alpha = 1,
        size = UDim2.new(1, 0, 1, 0),
        name = "ModalOverlay",
        z = 90,
        parent = screenGui,
    })
    Modal._overlay.Visible = false
    Modal._overlay.Active = true
end

function Modal.confirm(title, body, onConfirm, onCancel)
    if Modal._current then return end

    Modal._overlay.BackgroundTransparency = 1
    Modal._overlay.Visible = true
    Util.tween(Modal._overlay, Util.ease(), { BackgroundTransparency = 0.5 })

    local dialog = UI.frame({
        bg = PALETTE.BG_PANEL,
        size = UDim2.new(0, 340, 0, 180),
        pos = UDim2.new(0.5, -170, 0.5, -90),
        name = "ConfirmDialog",
        z = 91,
        parent = Modal._overlay,
    })
    UI.corner(14, dialog)
    UI.stroke(PALETTE.BORDER_LIT, 1, dialog)
    dialog.BackgroundTransparency = 1
    Util.tween(dialog, Util.ease(Enum.EasingStyle.Back), { BackgroundTransparency = 0 })
    Modal._current = dialog

    UI.padding(20, 20, dialog)

    local titleLbl = UI.label({
        text = title,
        color = PALETTE.TEXT_PRIMARY,
        size = 16,
        font = Enum.Font.GothamBold,
        sz = UDim2.new(1, 0, 0, 24),
        pos = UDim2.new(0, 20, 0, 20),
        z = 92,
        parent = dialog,
    })

    local bodyLbl = UI.label({
        text = body,
        color = PALETTE.TEXT_SECONDARY,
        size = 13,
        sz = UDim2.new(1, -40, 0, 60),
        pos = UDim2.new(0, 20, 0, 52),
        wrap = true,
        z = 92,
        parent = dialog,
    })

    local btnRow = UI.frame({
        bg = PALETTE.TRANSPARENT,
        alpha = 1,
        size = UDim2.new(1, -40, 0, 36),
        pos = UDim2.new(0, 20, 1, -56),
        z = 92,
        parent = dialog,
    })
    UI.list(Enum.FillDirection.Horizontal, 10, btnRow)

    local function closeModal()
        Util.tween(dialog, Util.ease(), { BackgroundTransparency = 1 })
        Util.tween(Modal._overlay, Util.ease(), { BackgroundTransparency = 1 })
        task.delay(0.25, function()
            Modal._overlay.Visible = false
            if dialog and dialog.Parent then dialog:Destroy() end
            Modal._current = nil
        end)
    end

    local cancelBtn = UI.button({
        text = "Cancel",
        bg = PALETTE.BG_CARD,
        color = PALETTE.TEXT_SECONDARY,
        sz = UDim2.new(0.48, 0, 1, 0),
        z = 93,
        parent = btnRow,
    })
    UI.corner(8, cancelBtn)
    attachButtonBehaviour(cancelBtn, PALETTE.BG_CARD, PALETTE.BG_HOVER, PALETTE.BG_HOVER)
    cancelBtn.MouseButton1Click:Connect(function()
        closeModal()
        if onCancel then task.spawn(onCancel) end
    end)

    local confirmBtn = UI.button({
        text = "Confirm",
        bg = PALETTE.ACCENT_DIM,
        color = PALETTE.TEXT_PRIMARY,
        sz = UDim2.new(0.48, 0, 1, 0),
        z = 93,
        parent = btnRow,
    })
    UI.corner(8, confirmBtn)
    attachButtonBehaviour(confirmBtn, PALETTE.ACCENT_DIM, PALETTE.ACCENT, PALETTE.ACCENT)
    confirmBtn.MouseButton1Click:Connect(function()
        closeModal()
        if onConfirm then task.spawn(onConfirm) end
    end)
end

-- ============================================================
-- MAIN APPLICATION
-- ============================================================

local App = {}
App._gui = nil
App._mainWin = nil
App._tabs = {}
App._tabBtns = {}
App._activeTabFrame = nil
App._scanProgressBar = nil
App._scanProgressLbl = nil
App._statsLabels = {}
App._findingsList = nil
App._logList = nil
App._apiInput = nil
App._scanBtn = nil
App._cancelBtn = nil

-- Stat counter display
function App.updateStats()
    local counts = { CRITICAL = 0, HIGH = 0, MEDIUM = 0, LOW = 0, INFO = 0 }
    for _, f in ipairs(State.findings) do
        local sev = f.severity or "INFO"
        if counts[sev] then counts[sev] = counts[sev] + 1 end
    end

    for sev, lbl in pairs(App._statsLabels) do
        if lbl and lbl.Parent then
            lbl.Text = tostring(counts[sev] or 0)
        end
    end
end

-- Log a scan message
function App.log(msg, kind)
    local entry = {
        time = Util.timestamp(),
        msg  = msg,
        kind = kind or "info",
    }
    table.insert(State.scanLog, 1, entry)

    if App._logList then
        local col = {
            info    = PALETTE.TEXT_SECONDARY,
            success = PALETTE.SUCCESS,
            error   = PALETTE.ERROR_COL,
            warning = PALETTE.WARNING,
            accent  = PALETTE.ACCENT,
        }
        local c = col[kind] or PALETTE.TEXT_SECONDARY

        local row = UI.frame({
            bg = PALETTE.TRANSPARENT,
            alpha = 1,
            size = UDim2.new(1, 0, 0, 0),
            name = "LogRow",
            z = 5,
            parent = App._logList,
        })
        row.AutomaticSize = Enum.AutomaticSize.Y

        local timeLbl = UI.label({
            text = entry.time,
            color = PALETTE.TEXT_MUTED,
            size = 11,
            font = Enum.Font.Code,
            sz = UDim2.new(0, 70, 0, 20),
            pos = UDim2.new(0, 0, 0, 0),
            z = 6,
            parent = row,
        })

        local msgLbl = UI.label({
            text = msg,
            color = c,
            size = 12,
            font = Enum.Font.Code,
            sz = UDim2.new(1, -78, 0, 0),
            pos = UDim2.new(0, 78, 0, 0),
            wrap = true,
            z = 6,
            parent = row,
        })
        msgLbl.AutomaticSize = Enum.AutomaticSize.Y
        row.Size = UDim2.new(1, 0, 0, 22)
    end
end

-- Set progress bar
function App.setProgress(pct, label)
    if App._scanProgressBar then
        Util.tween(App._scanProgressBar, Util.ease(), {
            Size = UDim2.new(pct, 0, 1, 0),
        })
    end
    if App._scanProgressLbl and label then
        App._scanProgressLbl.Text = label
    end
end

-- Render a finding card into the findings list
function App.addFindingCard(finding, listParent)
    if not listParent or not listParent.Parent then return end

    local sev = finding.severity or "INFO"
    local sevCfg = SEVERITY_CONFIG[sev] or SEVERITY_CONFIG.INFO

    local card = UI.frame({
        bg = PALETTE.BG_CARD,
        size = UDim2.new(1, -8, 0, 0),
        name = "FindingCard_" .. sev,
        z = 5,
        parent = listParent,
    })
    card.AutomaticSize = Enum.AutomaticSize.Y
    card.LayoutOrder = sevCfg.order * 1000 + #State.findings
    UI.corner(10, card)
    UI.stroke(sevCfg.color, 1, card, 0.5)

    -- Severity bar
    local sevBar = UI.frame({
        bg = sevCfg.color,
        size = UDim2.new(0, 3, 1, 0),
        name = "SevBar",
        z = 6,
        parent = card,
    })
    UI.corner(10, sevBar)

    local inner = UI.frame({
        bg = PALETTE.TRANSPARENT,
        alpha = 1,
        size = UDim2.new(1, -12, 0, 0),
        pos = UDim2.new(0, 12, 0, 0),
        name = "Inner",
        z = 6,
        parent = card,
    })
    inner.AutomaticSize = Enum.AutomaticSize.Y
    UI.padding(10, 10, inner)

    -- Header row
    local header = UI.frame({
        bg = PALETTE.TRANSPARENT,
        alpha = 1,
        size = UDim2.new(1, 0, 0, 26),
        name = "Header",
        z = 7,
        parent = inner,
    })

    local badge = UI.frame({
        bg = sevCfg.color,
        size = UDim2.new(0, 70, 0, 20),
        pos = UDim2.new(0, 0, 0, 3),
        name = "Badge",
        z = 8,
        parent = header,
    })
    UI.corner(4, badge)
    UI.label({
        text = sevCfg.icon .. " " .. sevCfg.label,
        color = PALETTE.BG_DEEP,
        size = 11,
        font = Enum.Font.GothamBold,
        sz = UDim2.new(1, 0, 1, 0),
        xalign = Enum.TextXAlignment.Center,
        z = 9,
        parent = badge,
    })

    local catLbl = UI.label({
        text = finding.category or "",
        color = PALETTE.TEXT_MUTED,
        size = 11,
        font = Enum.Font.Gotham,
        sz = UDim2.new(1, -160, 0, 26),
        pos = UDim2.new(0, 80, 0, 0),
        z = 8,
        parent = header,
    })

    -- Copy button
    local copyBtn = UI.button({
        text = "Copy",
        bg = PALETTE.BG_HOVER,
        color = PALETTE.TEXT_SECONDARY,
        size = 11,
        sz = UDim2.new(0, 50, 0, 22),
        pos = UDim2.new(1, -52, 0, 2),
        z = 8,
        parent = header,
    })
    UI.corner(6, copyBtn)
    attachButtonBehaviour(copyBtn, PALETTE.BG_HOVER, PALETTE.BORDER_LIT, PALETTE.ACCENT_DIM)
    copyBtn.MouseButton1Click:Connect(function()
        local txt = string.format("[%s] %s\nRemote: %s\nPath: %s\n\nDescription:\n%s\n\nRecommendation:\n%s",
            sev,
            finding.title or "",
            finding.remote or "",
            finding.path or "",
            finding.description or "",
            finding.recommendation or ""
        )
        pcall(function() setclipboard(txt) end)
        Toast.show("Finding copied to clipboard", "success")
    end)

    -- Title
    local titleLbl = UI.label({
        text = finding.title or "Unknown Issue",
        color = PALETTE.TEXT_PRIMARY,
        size = 14,
        font = Enum.Font.GothamBold,
        sz = UDim2.new(1, 0, 0, 20),
        pos = UDim2.new(0, 0, 0, 30),
        z = 7,
        parent = inner,
    })

    -- Remote path
    local pathLbl = UI.label({
        text = "📡 " .. (finding.path or finding.remote or "Unknown"),
        color = PALETTE.TEXT_ACCENT,
        size = 12,
        font = Enum.Font.Code,
        sz = UDim2.new(1, 0, 0, 18),
        pos = UDim2.new(0, 0, 0, 52),
        truncate = Enum.TextTruncate.AtEnd,
        z = 7,
        parent = inner,
    })

    -- Description (collapsible)
    local expanded = false
    local descLbl = UI.label({
        text = finding.description or "",
        color = PALETTE.TEXT_SECONDARY,
        size = 12,
        sz = UDim2.new(1, 0, 0, 0),
        pos = UDim2.new(0, 0, 0, 76),
        wrap = true,
        z = 7,
        parent = inner,
    })
    descLbl.AutomaticSize = Enum.AutomaticSize.Y
    descLbl.Visible = false

    local recLbl = UI.label({
        text = "💡 " .. (finding.recommendation or ""),
        color = PALETTE.SUCCESS,
        size = 12,
        sz = UDim2.new(1, 0, 0, 0),
        pos = UDim2.new(0, 0, 0, 76),
        wrap = true,
        z = 7,
        parent = inner,
    })
    recLbl.AutomaticSize = Enum.AutomaticSize.Y
    recLbl.Visible = false

    -- Expand button
    local expandBtn = UI.button({
        text = "▼ Expand",
        bg = PALETTE.TRANSPARENT,
        bgAlpha = 1,
        color = PALETTE.TEXT_MUTED,
        size = 11,
        sz = UDim2.new(1, 0, 0, 24),
        pos = UDim2.new(0, 0, 0, 74),
        z = 7,
        parent = inner,
    })

    expandBtn.MouseButton1Click:Connect(function()
        expanded = not expanded
        descLbl.Visible = expanded
        recLbl.Visible = expanded
        if expanded then
            recLbl.Position = UDim2.new(0, 0, 0, 0)
            expandBtn.Text = "▲ Collapse"
        else
            expandBtn.Text = "▼ Expand"
        end
    end)
end

-- Re-render findings list based on current filters
function App.refreshFindings()
    if not App._findingsList then return end

    -- Clear existing cards
    for _, child in ipairs(App._findingsList:GetChildren()) do
        if child:IsA("Frame") and child.Name:find("FindingCard") then
            child:Destroy()
        end
    end

    local filtered = {}
    for _, f in ipairs(State.findings) do
        local sev = f.severity or "INFO"
        local passFilter = (State.filterSeverity == "ALL" or sev == State.filterSeverity)
        local query = State.searchQuery:lower()
        local passSearch = query == ""
            or (f.title or ""):lower():find(query, 1, true)
            or (f.remote or ""):lower():find(query, 1, true)
            or (f.description or ""):lower():find(query, 1, true)
            or (f.category or ""):lower():find(query, 1, true)

        if passFilter and passSearch then
            table.insert(filtered, f)
        end
    end

    -- Sort
    if State.sortMode == "severity" then
        table.sort(filtered, function(a, b)
            local sa = (SEVERITY_CONFIG[a.severity] or SEVERITY_CONFIG.INFO).order
            local sb = (SEVERITY_CONFIG[b.severity] or SEVERITY_CONFIG.INFO).order
            return sa < sb
        end)
    elseif State.sortMode == "name" then
        table.sort(filtered, function(a, b)
            return (a.remote or "") < (b.remote or "")
        end)
    end

    for i, f in ipairs(filtered) do
        if i > CONFIG.MAX_FINDINGS_DISPLAY then break end
        App.addFindingCard(f, App._findingsList)
    end

    App.updateStats()
end

-- ============================================================
-- WINDOW DRAGGING
-- ============================================================

function App.setupDrag(handle, window)
    local dragging = false
    local dragStart = nil
    local startPos = nil

    local function clampWindow()
        if not window or not window.Parent then return end
        local vp = Util.getViewport()
        local inset = Util.getSafeInset()
        local wSize = window.AbsoluteSize
        local x = math.max(inset.X, math.min(vp.X - wSize.X - 8, window.AbsolutePosition.X))
        local y = math.max(inset.Y + 8, math.min(vp.Y - wSize.Y - 8, window.AbsolutePosition.Y))
        window.Position = UDim2.new(0, x, 0, y)
        State.windowPos = window.Position
    end

    handle.InputBegan:Connect(function(input)
        if input.UserInputType == Enum.UserInputType.MouseButton1
            or input.UserInputType == Enum.UserInputType.Touch then
            dragging = true
            dragStart = input.Position
            startPos = window.Position
        end
    end)

    UserInputService.InputChanged:Connect(function(input)
        if not dragging then return end
        if input.UserInputType == Enum.UserInputType.MouseMovement
            or input.UserInputType == Enum.UserInputType.Touch then
            local delta = input.Position - dragStart
            local vp = Util.getViewport()
            local inset = Util.getSafeInset()
            local wSize = window.AbsoluteSize

            local newX = Util.clamp(startPos.X.Offset + delta.X, inset.X, vp.X - wSize.X - 8)
            local newY = Util.clamp(startPos.Y.Offset + delta.Y, inset.Y + 8, vp.Y - wSize.Y - 8)

            window.Position = UDim2.new(0, newX, 0, newY)
            State.windowPos = window.Position
        end
    end)

    local function endDrag(input)
        if input.UserInputType == Enum.UserInputType.MouseButton1
            or input.UserInputType == Enum.UserInputType.Touch then
            dragging = false
            clampWindow()
        end
    end

    UserInputService.InputEnded:Connect(endDrag)
    handle.InputEnded:Connect(endDrag)
end

-- ============================================================
-- TAB SYSTEM
-- ============================================================

function App.switchTab(tabName)
    if State.activeTab == tabName then return end
    State.activeTab = tabName

    for name, frame in pairs(App._tabs) do
        if frame and frame.Parent then
            frame.Visible = (name == tabName)
        end
    end

    for name, btn in pairs(App._tabBtns) do
        if btn and btn.Parent then
            local isActive = (name == tabName)
            Util.tween(btn, Util.easeFast(), {
                BackgroundColor3 = isActive and PALETTE.ACCENT_DIM or PALETTE.BG_CARD,
                BackgroundTransparency = isActive and 0 or 0,
            })
            local lbl = btn:FindFirstChildWhichIsA("TextLabel")
            if lbl then
                lbl.TextColor3 = isActive and PALETTE.ACCENT_GLOW or PALETTE.TEXT_SECONDARY
            end
        end
    end
end

-- ============================================================
-- BUILD UI
-- ============================================================

function App.build()
    -- Cleanup old
    local old = PlayerGui:FindFirstChild("AuditorGui")
    if old then old:Destroy() end

    local screenGui = Instance.new("ScreenGui")
    screenGui.Name = "AuditorGui"
    screenGui.ResetOnSpawn = false
    screenGui.ZIndexBehavior = Enum.ZIndexBehavior.Sibling
    screenGui.IgnoreGuiInset = true
    screenGui.Parent = PlayerGui
    App._gui = screenGui

    Toast.init(screenGui)
    Modal.init(screenGui)

    -- ---- API KEY POPUP (shown before main window if no key) ----
    App.showApiKeyPrompt(screenGui, function(key)
        State.apiKey = key
        App.buildMainWindow(screenGui)
        Toast.show("API key saved. Ready to scan.", "success")
    end)
end

function App.showApiKeyPrompt(screenGui, onConfirm)
    local overlay = UI.frame({
        bg = Color3.fromRGB(0, 0, 0),
        alpha = 0.7,
        size = UDim2.new(1, 0, 1, 0),
        name = "KeyPromptOverlay",
        z = 80,
        parent = screenGui,
    })

    local dialog = UI.frame({
        bg = PALETTE.BG_PANEL,
        size = UDim2.new(0, 380, 0, 240),
        pos = UDim2.new(0.5, -190, 0.5, -120),
        name = "KeyDialog",
        z = 81,
        parent = overlay,
    })
    dialog.BackgroundTransparency = 1
    UI.corner(14, dialog)
    UI.stroke(PALETTE.ACCENT_DIM, 1, dialog)
    Util.tween(dialog, Util.ease(Enum.EasingStyle.Back), { BackgroundTransparency = 0 })

    UI.label({
        text = "🔐 Groq API Key Required",
        color = PALETTE.TEXT_PRIMARY,
        size = 16,
        font = Enum.Font.GothamBold,
        sz = UDim2.new(1, -40, 0, 28),
        pos = UDim2.new(0, 20, 0, 20),
        z = 82,
        parent = dialog,
    })

    UI.label({
        text = "Enter your Groq API key to enable AI-powered security auditing.",
        color = PALETTE.TEXT_SECONDARY,
        size = 12,
        sz = UDim2.new(1, -40, 0, 36),
        pos = UDim2.new(0, 20, 0, 52),
        wrap = true,
        z = 82,
        parent = dialog,
    })

    local inputFrame = UI.frame({
        bg = PALETTE.BG_INPUT,
        size = UDim2.new(1, -40, 0, 38),
        pos = UDim2.new(0, 20, 0, 100),
        z = 82,
        parent = dialog,
    })
    UI.corner(8, inputFrame)
    UI.stroke(PALETTE.BORDER, 1, inputFrame)

    local keyInput = UI.input({
        placeholder = "gsk_...",
        size = 13,
        sz = UDim2.new(1, -16, 1, 0),
        pos = UDim2.new(0, 8, 0, 0),
        z = 83,
        parent = inputFrame,
    })

    inputFrame.InputBegan:Connect(function()
        UI.stroke(PALETTE.ACCENT, 1, inputFrame)
    end)
    inputFrame.InputEnded:Connect(function()
        UI.stroke(PALETTE.BORDER, 1, inputFrame)
    end)
    keyInput.Focused:Connect(function()
        Util.tween(inputFrame, Util.easeFast(), { BackgroundColor3 = PALETTE.BG_HOVER })
    end)
    keyInput.FocusLost:Connect(function()
        Util.tween(inputFrame, Util.easeFast(), { BackgroundColor3 = PALETTE.BG_INPUT })
    end)

    local errLbl = UI.label({
        text = "",
        color = PALETTE.ERROR_COL,
        size = 11,
        sz = UDim2.new(1, -40, 0, 16),
        pos = UDim2.new(0, 20, 0, 142),
        z = 82,
        parent = dialog,
    })

    local confirmBtn = UI.button({
        text = "Start Auditor →",
        bg = PALETTE.ACCENT_DIM,
        color = PALETTE.TEXT_PRIMARY,
        size = 14,
        font = Enum.Font.GothamBold,
        sz = UDim2.new(1, -40, 0, 40),
        pos = UDim2.new(0, 20, 0, 164),
        z = 82,
        parent = dialog,
    })
    UI.corner(10, confirmBtn)
    attachButtonBehaviour(confirmBtn, PALETTE.ACCENT_DIM, PALETTE.ACCENT, Color3.fromRGB(70, 150, 220))

    local function tryConfirm()
        local key = keyInput.Text:match("^%s*(.-)%s*$")
        if key == "" then
            errLbl.Text = "API key cannot be empty."
            return
        end
        if not key:match("^gsk_") and not key:match("^groq_") then
            errLbl.Text = "Key should start with 'gsk_'. Continue anyway?"
        end
        Util.tween(overlay, Util.ease(), { BackgroundTransparency = 1 })
        Util.tween(dialog, Util.ease(), { BackgroundTransparency = 1 })
        task.delay(0.25, function()
            overlay:Destroy()
            onConfirm(key)
        end)
    end

    confirmBtn.MouseButton1Click:Connect(tryConfirm)
    keyInput.FocusLost:Connect(function(enter)
        if enter then tryConfirm() end
    end)
end

function App.buildMainWindow(screenGui)
    local vp = Util.getViewport()
    local isMobile = Util.isMobile()

    -- Responsive sizing
    local winW, winH
    if isMobile then
        winW = math.min(vp.X - 16, 420)
        winH = math.min(vp.Y - 40, vp.Y * 0.92)
    elseif Util.isTablet() then
        winW = math.min(vp.X - 40, 620)
        winH = math.min(vp.Y - 60, vp.Y * 0.88)
    else
        winW = math.min(vp.X - 60, 780)
        winH = math.min(vp.Y - 60, 620)
    end

    local startX = vp.X / 2 - winW / 2
    local startY = vp.Y / 2 - winH / 2

    if State.windowPos then
        startX = State.windowPos.X.Offset
        startY = State.windowPos.Y.Offset
    end

    local win = UI.frame({
        bg = PALETTE.BG_DEEP,
        size = UDim2.new(0, winW, 0, winH),
        pos = UDim2.new(0, startX, 0, startY),
        name = "MainWindow",
        z = 10,
        clip = true,
        parent = screenGui,
    })
    win.BackgroundTransparency = 1
    UI.corner(14, win)
    UI.stroke(PALETTE.BORDER, 1, win)
    App._mainWin = win

    Util.tween(win, Util.ease(Enum.EasingStyle.Back), { BackgroundTransparency = 0 })

    -- Drop shadow simulation via outer frame
    local shadow = UI.frame({
        bg = Color3.fromRGB(0, 0, 0),
        alpha = 0.5,
        size = UDim2.new(1, 16, 1, 16),
        pos = UDim2.new(0, -8, 0, -8),
        name = "Shadow",
        z = 9,
        clip = false,
        parent = win,
    })
    UI.corner(18, shadow)

    -- ---- TITLE BAR ----
    local titleBar = UI.frame({
        bg = PALETTE.BG_PANEL,
        size = UDim2.new(1, 0, 0, 48),
        name = "TitleBar",
        z = 11,
        parent = win,
    })
    UI.gradient(
        Color3.fromRGB(20, 23, 34),
        Color3.fromRGB(14, 16, 24),
        180, titleBar
    )

    -- Window title
    local titleIcon = UI.label({
        text = "🛡️",
        size = 20,
        sz = UDim2.new(0, 32, 1, 0),
        pos = UDim2.new(0, 12, 0, 0),
        xalign = Enum.TextXAlignment.Center,
        z = 12,
        parent = titleBar,
    })

    local titleLbl = UI.label({
        text = "AI Security Auditor",
        color = PALETTE.TEXT_PRIMARY,
        size = 15,
        font = Enum.Font.GothamBold,
        sz = UDim2.new(0, 200, 1, 0),
        pos = UDim2.new(0, 48, 0, 0),
        z = 12,
        parent = titleBar,
    })

    local madeby = UI.label({
        text = "Made by Jordan",
        color = PALETTE.TEXT_MUTED,
        size = 11,
        font = Enum.Font.Gotham,
        sz = UDim2.new(0, 120, 1, 0),
        pos = UDim2.new(0, 48, 0, 0),
        xalign = Enum.TextXAlignment.Left,
        z = 12,
        parent = titleBar,
    })
    madeby.Position = UDim2.new(0, 48 + 180, 0, 0)
    madeby.TextColor3 = PALETTE.TEXT_MUTED

    -- Window control buttons
    local btnArea = UI.frame({
        bg = PALETTE.TRANSPARENT,
        alpha = 1,
        size = UDim2.new(0, 80, 0, 30),
        pos = UDim2.new(1, -88, 0.5, -15),
        z = 12,
        parent = titleBar,
    })
    UI.list(Enum.FillDirection.Horizontal, 6, btnArea)

    local function makeWinBtn(label, col)
        local b = UI.button({
            text = label,
            bg = col,
            color = PALETTE.BG_DEEP,
            size = 11,
            font = Enum.Font.GothamBold,
            sz = UDim2.new(0, 24, 0, 24),
            z = 13,
            parent = btnArea,
        })
        UI.corner(12, b)
        return b
    end

    local minBtn = makeWinBtn("−", Color3.fromRGB(255, 190, 50))
    local closeBtn = makeWinBtn("✕", Color3.fromRGB(248, 81, 73))

    local minimised = false
    local prevH = winH

    minBtn.MouseButton1Click:Connect(function()
        minimised = not minimised
        if minimised then
            prevH = win.AbsoluteSize.Y
            Util.tween(win, Util.ease(Enum.EasingStyle.Quart), {
                Size = UDim2.new(0, winW, 0, 48),
            })
            State.minimised = true
        else
            Util.tween(win, Util.ease(Enum.EasingStyle.Back), {
                Size = UDim2.new(0, winW, 0, prevH),
            })
            State.minimised = false
        end
    end)

    closeBtn.MouseButton1Click:Connect(function()
        Modal.confirm(
            "Close Auditor",
            "Are you sure you want to close the AI Security Auditor? Any unsaved results will be lost.",
            function()
                Util.tween(win, Util.ease(), { BackgroundTransparency = 1 })
                task.delay(0.3, function()
                    if screenGui and screenGui.Parent then screenGui:Destroy() end
                end)
            end
        )
    end)

    App.setupDrag(titleBar, win)

    -- ---- TAB BAR ----
    local tabBar = UI.frame({
        bg = PALETTE.BG_PANEL,
        size = UDim2.new(1, 0, 0, 40),
        pos = UDim2.new(0, 0, 0, 48),
        name = "TabBar",
        z = 11,
        parent = win,
    })
    UI.stroke(PALETTE.BORDER, 1, tabBar)

    local tabScroll = UI.scroll({
        bg = PALETTE.TRANSPARENT,
        alpha = 1,
        size = UDim2.new(1, 0, 1, 0),
        barSize = 0,
        dir = Enum.ScrollingDirection.X,
        autoCanvas = Enum.AutomaticSize.X,
        name = "TabScroll",
        z = 12,
        parent = tabBar,
    })
    UI.list(Enum.FillDirection.Horizontal, 4, tabScroll)
    UI.padding(8, 6, tabScroll)

    local tabs = {
        { id = "dashboard", label = "📊 Dashboard" },
        { id = "scan",      label = "🔍 Scan" },
        { id = "findings",  label = "🚨 Findings" },
        { id = "log",       label = "📋 Log" },
        { id = "settings",  label = "⚙️ Settings" },
    }

    for _, tab in ipairs(tabs) do
        local btn = UI.button({
            text = tab.label,
            bg = PALETTE.BG_CARD,
            color = PALETTE.TEXT_SECONDARY,
            size = 13,
            sz = UDim2.new(0, 0, 0, 28),
            z = 13,
            parent = tabScroll,
        })
        btn.AutomaticSize = Enum.AutomaticSize.X
        btn.TextSize = 13
        UI.corner(6, btn)
        UI.padding(12, 0, btn)

        App._tabBtns[tab.id] = btn

        btn.MouseButton1Click:Connect(function()
            App.switchTab(tab.id)
        end)
    end

    -- ---- CONTENT AREA ----
    local contentArea = UI.frame({
        bg = PALETTE.BG_DEEP,
        size = UDim2.new(1, 0, 1, -88),
        pos = UDim2.new(0, 0, 0, 88),
        name = "Content",
        z = 11,
        parent = win,
    })

    -- Build each tab
    App.buildDashboardTab(contentArea)
    App.buildScanTab(contentArea)
    App.buildFindingsTab(contentArea)
    App.buildLogTab(contentArea)
    App.buildSettingsTab(contentArea)

    -- Activate default tab
    App.switchTab("dashboard")

    -- Viewport resize handler
    local vpConn
    vpConn = Camera:GetPropertyChangedSignal("ViewportSize"):Connect(function()
        if not win or not win.Parent then
            vpConn:Disconnect()
            return
        end
        local newVp = Util.getViewport()
        local newW = Util.clamp(win.AbsoluteSize.X, 300, newVp.X - 20)
        local newH = Util.clamp(win.AbsoluteSize.Y, 300, newVp.Y - 20)
        local newX = Util.clamp(win.AbsolutePosition.X, 8, newVp.X - newW - 8)
        local newY = Util.clamp(win.AbsolutePosition.Y, 8, newVp.Y - newH - 8)
        win.Size = UDim2.new(0, newW, 0, newH)
        win.Position = UDim2.new(0, newX, 0, newY)
    end)
end

-- ============================================================
-- TAB: DASHBOARD
-- ============================================================

function App.buildDashboardTab(parent)
    local tab = UI.scroll({
        bg = PALETTE.TRANSPARENT,
        alpha = 1,
        size = UDim2.new(1, 0, 1, 0),
        name = "Tab_dashboard",
        z = 12,
        parent = parent,
    })
    App._tabs["dashboard"] = tab
    UI.list(Enum.FillDirection.Vertical, 12, tab)
    UI.padding(14, 14, tab)

    -- Header
    local hdr = UI.frame({
        bg = PALETTE.BG_CARD,
        size = UDim2.new(1, 0, 0, 80),
        name = "Header",
        z = 13,
        parent = tab,
    })
    UI.corner(12, hdr)
    UI.gradient(
        Color3.fromRGB(20, 35, 60),
        Color3.fromRGB(14, 20, 35),
        135, hdr
    )
    UI.padding(16, 0, hdr)

    UI.label({
        text = "🛡️ Security Audit Dashboard",
        color = PALETTE.TEXT_PRIMARY,
        size = 18,
        font = Enum.Font.GothamBold,
        sz = UDim2.new(1, 0, 0, 32),
        pos = UDim2.new(0, 16, 0, 14),
        z = 14,
        parent = hdr,
    })
    UI.label({
        text = "AI-powered Roblox vulnerability scanner using Groq LLaMA 70B",
        color = PALETTE.TEXT_MUTED,
        size = 12,
        sz = UDim2.new(1, 0, 0, 24),
        pos = UDim2.new(0, 16, 0, 46),
        z = 14,
        parent = hdr,
    })

    -- Severity stat cards
    local statsRow = UI.frame({
        bg = PALETTE.TRANSPARENT,
        alpha = 1,
        size = UDim2.new(1, 0, 0, 70),
        name = "StatsRow",
        z = 13,
        parent = tab,
    })
    UI.list(Enum.FillDirection.Horizontal, 8, statsRow)

    local sevOrder = { "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO" }
    for _, sev in ipairs(sevOrder) do
        local cfg = SEVERITY_CONFIG[sev]
        local card = UI.frame({
            bg = PALETTE.BG_CARD,
            size = UDim2.new(0.19, -4, 1, 0),
            name = "Stat_" .. sev,
            z = 14,
            parent = statsRow,
        })
        UI.corner(10, card)
        UI.stroke(cfg.color, 1, card, 0.4)

        UI.label({
            text = cfg.icon,
            size = 18,
            sz = UDim2.new(1, 0, 0, 26),
            pos = UDim2.new(0, 0, 0, 8),
            xalign = Enum.TextXAlignment.Center,
            z = 15,
            parent = card,
        })

        local numLbl = UI.label({
            text = "0",
            color = cfg.color,
            size = 20,
            font = Enum.Font.GothamBold,
            sz = UDim2.new(1, 0, 0, 26),
            pos = UDim2.new(0, 0, 0, 30),
            xalign = Enum.TextXAlignment.Center,
            z = 15,
            parent = card,
        })

        UI.label({
            text = sev,
            color = PALETTE.TEXT_MUTED,
            size = 9,
            font = Enum.Font.GothamMedium,
            sz = UDim2.new(1, 0, 0, 16),
            pos = UDim2.new(0, 0, 0, 52),
            xalign = Enum.TextXAlignment.Center,
            z = 15,
            parent = card,
        })

        App._statsLabels[sev] = numLbl
    end

    -- Quick scan button
    local quickScanBtn = UI.button({
        text = "🔍  Run Full Security Scan",
        bg = PALETTE.ACCENT_DIM,
        color = PALETTE.TEXT_PRIMARY,
        size = 15,
        font = Enum.Font.GothamBold,
        sz = UDim2.new(1, 0, 0, 46),
        name = "QuickScan",
        z = 13,
        parent = tab,
    })
    UI.corner(10, quickScanBtn)
    attachButtonBehaviour(quickScanBtn, PALETTE.ACCENT_DIM, PALETTE.ACCENT, Color3.fromRGB(60, 140, 210))
    quickScanBtn.MouseButton1Click:Connect(function()
        App.switchTab("scan")
        task.delay(0.1, function()
            App.startScan()
        end)
    end)

    -- Info cards
    local infoCards = {
        { icon = "🔴", title = "RemoteEvent Analysis", desc = "Detects unvalidated, rate-limited and unsafe FireServer calls" },
        { icon = "⚡", title = "RemoteFunction Auditing", desc = "Identifies dangerous InvokeServer patterns and return value spoofing" },
        { icon = "🕵️", title = "Privilege Escalation", desc = "Finds admin/economy operations exposed to regular clients" },
        { icon = "📦", title = "Data Leakage Detection", desc = "Spots sensitive data returned to clients without authorization" },
    }

    for _, info in ipairs(infoCards) do
        local card = UI.frame({
            bg = PALETTE.BG_CARD,
            size = UDim2.new(1, 0, 0, 56),
            name = "InfoCard",
            z = 13,
            parent = tab,
        })
        UI.corner(10, card)
        UI.padding(14, 0, card)

        UI.label({
            text = info.icon,
            size = 20,
            sz = UDim2.new(0, 30, 1, 0),
            pos = UDim2.new(0, 14, 0, 0),
            xalign = Enum.TextXAlignment.Center,
            z = 14,
            parent = card,
        })
        UI.label({
            text = info.title,
            color = PALETTE.TEXT_PRIMARY,
            size = 13,
            font = Enum.Font.GothamBold,
            sz = UDim2.new(1, -56, 0, 24),
            pos = UDim2.new(0, 48, 0, 8),
            z = 14,
            parent = card,
        })
        UI.label({
            text = info.desc,
            color = PALETTE.TEXT_SECONDARY,
            size = 11,
            sz = UDim2.new(1, -56, 0, 20),
            pos = UDim2.new(0, 48, 0, 30),
            z = 14,
            parent = card,
        })
    end
end

-- ============================================================
-- TAB: SCAN
-- ============================================================

function App.buildScanTab(parent)
    local tab = UI.frame({
        bg = PALETTE.BG_DEEP,
        size = UDim2.new(1, 0, 1, 0),
        name = "Tab_scan",
        z = 12,
        parent = parent,
    })
    App._tabs["scan"] = tab

    local inner = UI.scroll({
        bg = PALETTE.TRANSPARENT,
        alpha = 1,
        size = UDim2.new(1, 0, 1, 0),
        name = "ScanInner",
        z = 13,
        parent = tab,
    })
    UI.list(Enum.FillDirection.Vertical, 12, inner)
    UI.padding(14, 14, inner)

    -- Progress section
    local progCard = UI.frame({
        bg = PALETTE.BG_CARD,
        size = UDim2.new(1, 0, 0, 90),
        name = "ProgressCard",
        z = 14,
        parent = inner,
    })
    UI.corner(12, progCard)
    UI.padding(16, 0, progCard)

    UI.label({
        text = "Scan Progress",
        color = PALETTE.TEXT_PRIMARY,
        size = 13,
        font = Enum.Font.GothamBold,
        sz = UDim2.new(1, 0, 0, 24),
        pos = UDim2.new(0, 16, 0, 12),
        z = 15,
        parent = progCard,
    })

    local progStatusLbl = UI.label({
        text = "Ready to scan",
        color = PALETTE.TEXT_SECONDARY,
        size = 12,
        sz = UDim2.new(1, 0, 0, 20),
        pos = UDim2.new(0, 16, 0, 34),
        z = 15,
        parent = progCard,
    })
    App._scanProgressLbl = progStatusLbl

    local progBg = UI.frame({
        bg = PALETTE.BG_INPUT,
        size = UDim2.new(1, -32, 0, 8),
        pos = UDim2.new(0, 16, 0, 62),
        name = "ProgBg",
        z = 15,
        parent = progCard,
    })
    UI.corner(4, progBg)

    local progFill = UI.frame({
        bg = PALETTE.ACCENT,
        size = UDim2.new(0, 0, 1, 0),
        name = "ProgFill",
        z = 16,
        parent = progBg,
    })
    UI.corner(4, progFill)
    UI.gradient(PALETTE.ACCENT, PALETTE.ACCENT_GLOW, 0, progFill)
    App._scanProgressBar = progFill

    -- Scan control buttons
    local btnRow = UI.frame({
        bg = PALETTE.TRANSPARENT,
        alpha = 1,
        size = UDim2.new(1, 0, 0, 44),
        name = "BtnRow",
        z = 14,
        parent = inner,
    })
    UI.list(Enum.FillDirection.Horizontal, 10, btnRow)

    local scanBtn = UI.button({
        text = "▶  Start Scan",
        bg = PALETTE.ACCENT_DIM,
        color = PALETTE.TEXT_PRIMARY,
        size = 14,
        font = Enum.Font.GothamBold,
        sz = UDim2.new(0.6, -5, 1, 0),
        z = 15,
        parent = btnRow,
    })
    UI.corner(10, scanBtn)
    attachButtonBehaviour(scanBtn, PALETTE.ACCENT_DIM, PALETTE.ACCENT, Color3.fromRGB(60, 140, 210))
    App._scanBtn = scanBtn

    local cancelBtn = UI.button({
        text = "⏹  Cancel",
        bg = PALETTE.BG_CARD,
        color = PALETTE.TEXT_SECONDARY,
        size = 14,
        font = Enum.Font.GothamBold,
        sz = UDim2.new(0.4, -5, 1, 0),
        z = 15,
        parent = btnRow,
    })
    UI.corner(10, cancelBtn)
    attachButtonBehaviour(cancelBtn, PALETTE.BG_CARD, PALETTE.BG_HOVER, PALETTE.ERROR_COL)
    cancelBtn.Active = false
    cancelBtn.BackgroundTransparency = 0.4
    App._cancelBtn = cancelBtn

    scanBtn.MouseButton1Click:Connect(function()
        App.startScan()
    end)

    cancelBtn.MouseButton1Click:Connect(function()
        if State.isScanning then
            State.scanCancelled = true
            App.log("Scan cancelled by user.", "warning")
            Toast.show("Scan cancelled.", "warning")
        end
    end)

    -- Scan info
    local remoteCountCard = UI.frame({
        bg = PALETTE.BG_CARD,
        size = UDim2.new(1, 0, 0, 80),
        name = "RemoteCount",
        z = 14,
        parent = inner,
    })
    UI.corner(12, remoteCountCard)
    UI.padding(16, 12, remoteCountCard)
    UI.list(Enum.FillDirection.Horizontal, 0, remoteCountCard)

    local function makeCountBox(label, valId)
        local box = UI.frame({
            bg = PALETTE.BG_INPUT,
            size = UDim2.new(0.33, -4, 1, 0),
            name = "CountBox_" .. label,
            z = 15,
            parent = remoteCountCard,
        })
        UI.corner(8, box)

        local val = UI.label({
            text = "0",
            color = PALETTE.ACCENT,
            size = 22,
            font = Enum.Font.GothamBold,
            sz = UDim2.new(1, 0, 0, 32),
            pos = UDim2.new(0, 0, 0, 8),
            xalign = Enum.TextXAlignment.Center,
            z = 16,
            parent = box,
        })
        UI.label({
            text = label,
            color = PALETTE.TEXT_MUTED,
            size = 10,
            sz = UDim2.new(1, 0, 0, 18),
            pos = UDim2.new(0, 0, 0, 40),
            xalign = Enum.TextXAlignment.Center,
            z = 16,
            parent = box,
        })
        return val
    end

    App._remoteCountLabels = {
        events    = makeCountBox("RemoteEvents"),
        functions = makeCountBox("RemoteFunctions"),
        bindables = makeCountBox("Bindables"),
    }

    -- Model info
    local modelCard = UI.frame({
        bg = PALETTE.BG_CARD,
        size = UDim2.new(1, 0, 0, 54),
        name = "ModelCard",
        z = 14,
        parent = inner,
    })
    UI.corner(12, modelCard)
    UI.padding(14, 0, modelCard)

    UI.label({
        text = "🤖 AI Model",
        color = PALETTE.TEXT_MUTED,
        size = 11,
        sz = UDim2.new(1, 0, 0, 20),
        pos = UDim2.new(0, 14, 0, 8),
        z = 15,
        parent = modelCard,
    })
    UI.label({
        text = CONFIG.GROQ_MODEL,
        color = PALETTE.ACCENT,
        size = 14,
        font = Enum.Font.GothamBold,
        sz = UDim2.new(1, 0, 0, 24),
        pos = UDim2.new(0, 14, 0, 26),
        z = 15,
        parent = modelCard,
    })
end

-- ============================================================
-- TAB: FINDINGS
-- ============================================================

function App.buildFindingsTab(parent)
    local tab = UI.frame({
        bg = PALETTE.BG_DEEP,
        size = UDim2.new(1, 0, 1, 0),
        name = "Tab_findings",
        z = 12,
        parent = parent,
    })
    App._tabs["findings"] = tab

    -- Toolbar
    local toolbar = UI.frame({
        bg = PALETTE.BG_PANEL,
        size = UDim2.new(1, 0, 0, 46),
        name = "Toolbar",
        z = 13,
        parent = tab,
    })
    UI.stroke(PALETTE.BORDER, 1, toolbar)
    UI.padding(10, 0, toolbar)

    -- Search box
    local searchFrame = UI.frame({
        bg = PALETTE.BG_INPUT,
        size = UDim2.new(0.38, 0, 0, 30),
        pos = UDim2.new(0, 10, 0.5, -15),
        name = "SearchFrame",
        z = 14,
        parent = toolbar,
    })
    UI.corner(8, searchFrame)
    UI.stroke(PALETTE.BORDER, 1, searchFrame)

    UI.label({
        text = "🔍",
        size = 13,
        sz = UDim2.new(0, 26, 1, 0),
        xalign = Enum.TextXAlignment.Center,
        z = 15,
        parent = searchFrame,
    })

    local searchInput = UI.input({
        placeholder = "Search findings...",
        size = 12,
        sz = UDim2.new(1, -28, 1, 0),
        pos = UDim2.new(0, 26, 0, 0),
        z = 15,
        parent = searchFrame,
    })

    searchInput:GetPropertyChangedSignal("Text"):Connect(function()
        State.searchQuery = searchInput.Text
        App.refreshFindings()
    end)

    -- Filter buttons
    local filterRow = UI.frame({
        bg = PALETTE.TRANSPARENT,
        alpha = 1,
        size = UDim2.new(0.58, -10, 0, 30),
        pos = UDim2.new(0.42, 0, 0.5, -15),
        name = "FilterRow",
        z = 14,
        parent = toolbar,
    })
    UI.list(Enum.FillDirection.Horizontal, 4, filterRow)

    local filters = { "ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO" }
    App._filterBtns = {}

    for _, f in ipairs(filters) do
        local cfg = SEVERITY_CONFIG[f]
        local col = cfg and cfg.color or PALETTE.ACCENT
        local isActive = (f == "ALL")

        local btn = UI.button({
            text = f,
            bg = isActive and PALETTE.ACCENT_DIM or PALETTE.BG_CARD,
            color = isActive and PALETTE.TEXT_PRIMARY or PALETTE.TEXT_MUTED,
            size = 11,
            font = Enum.Font.GothamBold,
            sz = UDim2.new(0, 0, 1, 0),
            z = 15,
            parent = filterRow,
        })
        btn.AutomaticSize = Enum.AutomaticSize.X
        UI.corner(6, btn)
        UI.padding(8, 0, btn)
        App._filterBtns[f] = btn

        btn.MouseButton1Click:Connect(function()
            State.filterSeverity = f
            for fk, fb in pairs(App._filterBtns) do
                local fc = SEVERITY_CONFIG[fk]
                local fc_col = fc and fc.color or PALETTE.ACCENT
                local act = (fk == f)
                Util.tween(fb, Util.easeFast(), {
                    BackgroundColor3 = act and PALETTE.ACCENT_DIM or PALETTE.BG_CARD,
                })
                local fl = fb:FindFirstChildWhichIsA("TextLabel")
                if fl then fl.TextColor3 = act and PALETTE.TEXT_PRIMARY or PALETTE.TEXT_MUTED end
            end
            App.refreshFindings()
        end)
    end

    -- Findings scroll list
    local findingsScroll = UI.scroll({
        bg = PALETTE.TRANSPARENT,
        alpha = 1,
        size = UDim2.new(1, 0, 1, -46),
        pos = UDim2.new(0, 0, 0, 46),
        name = "FindingsScroll",
        z = 13,
        parent = tab,
    })
    UI.list(Enum.FillDirection.Vertical, 8, findingsScroll)
    UI.padding(10, 10, findingsScroll)
    App._findingsList = findingsScroll

    -- Empty state
    local emptyLbl = UI.label({
        text = "No findings yet.\nRun a scan from the Scan tab.",
        color = PALETTE.TEXT_MUTED,
        size = 14,
        sz = UDim2.new(1, 0, 0, 60),
        pos = UDim2.new(0, 0, 0.4, 0),
        xalign = Enum.TextXAlignment.Center,
        wrap = true,
        name = "EmptyState",
        z = 14,
        parent = findingsScroll,
    })
    App._findingsEmpty = emptyLbl
end

-- ============================================================
-- TAB: LOG
-- ============================================================

function App.buildLogTab(parent)
    local tab = UI.frame({
        bg = PALETTE.BG_DEEP,
        size = UDim2.new(1, 0, 1, 0),
        name = "Tab_log",
        z = 12,
        parent = parent,
    })
    App._tabs["log"] = tab

    -- Header bar
    local hdr = UI.frame({
        bg = PALETTE.BG_PANEL,
        size = UDim2.new(1, 0, 0, 40),
        name = "LogHeader",
        z = 13,
        parent = tab,
    })
    UI.padding(10, 0, hdr)

    UI.label({
        text = "📋 Scan Log",
        color = PALETTE.TEXT_PRIMARY,
        size = 13,
        font = Enum.Font.GothamBold,
        sz = UDim2.new(0.6, 0, 1, 0),
        pos = UDim2.new(0, 10, 0, 0),
        z = 14,
        parent = hdr,
    })

    local clearBtn = UI.button({
        text = "Clear Log",
        bg = PALETTE.BG_CARD,
        color = PALETTE.TEXT_SECONDARY,
        size = 11,
        sz = UDim2.new(0, 80, 0, 26),
        pos = UDim2.new(1, -90, 0.5, -13),
        z = 14,
        parent = hdr,
    })
    UI.corner(6, clearBtn)
    attachButtonBehaviour(clearBtn, PALETTE.BG_CARD, PALETTE.BG_HOVER, PALETTE.ERROR_COL)
    clearBtn.MouseButton1Click:Connect(function()
        State.scanLog = {}
        if App._logList then
            for _, c in ipairs(App._logList:GetChildren()) do
                if c:IsA("Frame") then c:Destroy() end
            end
        end
    end)

    local logScroll = UI.scroll({
        bg = PALETTE.BG_INPUT,
        size = UDim2.new(1, 0, 1, -40),
        pos = UDim2.new(0, 0, 0, 40),
        name = "LogScroll",
        z = 13,
        parent = tab,
    })
    UI.list(Enum.FillDirection.Vertical, 2, logScroll)
    UI.padding(10, 6, logScroll)
    App._logList = logScroll
end

-- ============================================================
-- TAB: SETTINGS
-- ============================================================

function App.buildSettingsTab(parent)
    local tab = UI.scroll({
        bg = PALETTE.BG_DEEP,
        alpha = 0,
        size = UDim2.new(1, 0, 1, 0),
        name = "Tab_settings",
        z = 12,
        parent = parent,
    })
    App._tabs["settings"] = tab
    UI.list(Enum.FillDirection.Vertical, 12, tab)
    UI.padding(14, 14, tab)

    local function sectionHeader(text)
        UI.label({
            text = text,
            color = PALETTE.TEXT_MUTED,
            size = 11,
            font = Enum.Font.GothamBold,
            sz = UDim2.new(1, 0, 0, 20),
            z = 13,
            parent = tab,
        })
    end

    local function settingRow(label, desc, widget)
        local row = UI.frame({
            bg = PALETTE.BG_CARD,
            size = UDim2.new(1, 0, 0, 62),
            name = "SettingRow_" .. label,
            z = 13,
            parent = tab,
        })
        UI.corner(10, row)
        UI.padding(14, 0, row)

        UI.label({
            text = label,
            color = PALETTE.TEXT_PRIMARY,
            size = 13,
            font = Enum.Font.GothamBold,
            sz = UDim2.new(0.7, 0, 0, 24),
            pos = UDim2.new(0, 14, 0, 10),
            z = 14,
            parent = row,
        })
        UI.label({
            text = desc,
            color = PALETTE.TEXT_SECONDARY,
            size = 11,
            sz = UDim2.new(0.7, 0, 0, 20),
            pos = UDim2.new(0, 14, 0, 34),
            z = 14,
            parent = row,
        })

        if widget then widget(row) end
        return row
    end

    sectionHeader("API CONFIGURATION")

    -- API key row
    local apiRow = UI.frame({
        bg = PALETTE.BG_CARD,
        size = UDim2.new(1, 0, 0, 78),
        name = "ApiKeyRow",
        z = 13,
        parent = tab,
    })
    UI.corner(10, apiRow)
    UI.padding(14, 10, apiRow)

    UI.label({
        text = "Groq API Key",
        color = PALETTE.TEXT_PRIMARY,
        size = 13,
        font = Enum.Font.GothamBold,
        sz = UDim2.new(1, 0, 0, 22),
        pos = UDim2.new(0, 14, 0, 10),
        z = 14,
        parent = apiRow,
    })

    local apiInputFrame = UI.frame({
        bg = PALETTE.BG_INPUT,
        size = UDim2.new(1, -28, 0, 32),
        pos = UDim2.new(0, 14, 0, 36),
        z = 14,
        parent = apiRow,
    })
    UI.corner(8, apiInputFrame)
    UI.stroke(PALETTE.BORDER, 1, apiInputFrame)

    local apiInput = UI.input({
        text = State.apiKey,
        placeholder = "gsk_...",
        size = 12,
        sz = UDim2.new(1, -16, 1, 0),
        pos = UDim2.new(0, 8, 0, 0),
        z = 15,
        parent = apiInputFrame,
    })
    App._apiInput = apiInput

    apiInput:GetPropertyChangedSignal("Text"):Connect(function()
        State.apiKey = apiInput.Text
    end)

    apiInput.Focused:Connect(function()
        Util.tween(apiInputFrame, Util.easeFast(), { BackgroundColor3 = PALETTE.BG_HOVER })
    end)
    apiInput.FocusLost:Connect(function()
        Util.tween(apiInputFrame, Util.easeFast(), { BackgroundColor3 = PALETTE.BG_INPUT })
        State.apiKey = apiInput.Text
    end)

    sectionHeader("SCAN OPTIONS")

    settingRow("Max Tokens", "Maximum tokens for AI response (" .. CONFIG.MAX_TOKENS .. ")", function(row)
        UI.label({
            text = tostring(CONFIG.MAX_TOKENS),
            color = PALETTE.ACCENT,
            size = 13,
            font = Enum.Font.GothamBold,
            sz = UDim2.new(0.28, -14, 0, 24),
            pos = UDim2.new(0.72, 0, 0, 10),
            xalign = Enum.TextXAlignment.Right,
            z = 14,
            parent = row,
        })
    end)

    settingRow("AI Model", "Using " .. CONFIG.GROQ_MODEL, function(row)
        UI.label({
            text = "LLaMA 70B",
            color = PALETTE.ACCENT,
            size = 12,
            sz = UDim2.new(0.28, -14, 0, 24),
            pos = UDim2.new(0.72, 0, 0, 10),
            xalign = Enum.TextXAlignment.Right,
            z = 14,
            parent = row,
        })
    end)

    sectionHeader("ABOUT")

    local aboutCard = UI.frame({
        bg = PALETTE.BG_CARD,
        size = UDim2.new(1, 0, 0, 80),
        name = "About",
        z = 13,
        parent = tab,
    })
    UI.corner(10, aboutCard)
    UI.padding(14, 12, aboutCard)

    UI.label({ text = "🛡️ AI Security Auditor v1.0", color = PALETTE.TEXT_PRIMARY, size = 14, font = Enum.Font.GothamBold, sz = UDim2.new(1, 0, 0, 22), pos = UDim2.new(0, 14, 0, 12), z = 14, parent = aboutCard })
    UI.label({ text = "Made by Jordan  •  Powered by Groq LLaMA 70B  •  Delta Executor", color = PALETTE.TEXT_MUTED, size = 11, sz = UDim2.new(1, 0, 0, 18), pos = UDim2.new(0, 14, 0, 36), z = 14, parent = aboutCard })
    UI.label({ text = "Identifies RemoteEvent exploits, god mode vectors, info leakage & more.", color = PALETTE.TEXT_SECONDARY, size = 11, sz = UDim2.new(1, 0, 0, 18), pos = UDim2.new(0, 14, 0, 56), z = 14, parent = aboutCard })
end

-- ============================================================
-- SCAN ORCHESTRATION
-- ============================================================

function App.setScanningState(scanning)
    State.isScanning = scanning
    if App._scanBtn then
        App._scanBtn.Active = not scanning
        App._scanBtn.BackgroundTransparency = scanning and 0.5 or 0
        App._scanBtn.Text = scanning and "⏳ Scanning..." or "▶  Start Scan"
    end
    if App._cancelBtn then
        App._cancelBtn.Active = scanning
        App._cancelBtn.BackgroundTransparency = scanning and 0 or 0.4
    end
end

function App.startScan()
    if State.isScanning then
        Toast.show("A scan is already in progress.", "warning")
        return
    end

    if not State.apiKey or State.apiKey == "" then
        Toast.show("Please enter your Groq API key in Settings.", "error")
        App.switchTab("settings")
        return
    end

    State.isScanning = true
    State.scanCancelled = false
    State.findings = {}
    State.scanStartTime = tick()

    App.setScanningState(true)
    App.setProgress(0, "Initialising scan...")
    App.log("=== SCAN STARTED ===", "accent")
    App.log("Collecting remote instances...", "info")
    Toast.show("Scan started", "info")

    -- Switch to scan tab to show progress
    App.switchTab("scan")

    task.spawn(function()
        -- Step 1: Collect remotes
        local remotes
        local ok1, err1 = pcall(function()
            remotes = Scanner.collectRemotes()
        end)

        if not ok1 or not remotes then
            App.log("ERROR collecting remotes: " .. tostring(err1), "error")
            Toast.show("Failed to scan game instances.", "error")
            App.setScanningState(false)
            App.setProgress(0, "Scan failed")
            return
        end

        if State.scanCancelled then
            App.setScanningState(false)
            App.setProgress(0, "Cancelled")
            return
        end

        State.remoteEvents    = remotes.events
        State.remoteFunctions = remotes.functions
        State.bindableEvents  = remotes.bindables

        local totalRemotes = #remotes.events + #remotes.functions + #remotes.bindables

        -- Update count labels
        if App._remoteCountLabels then
            App._remoteCountLabels.events.Text    = tostring(#remotes.events)
            App._remoteCountLabels.functions.Text = tostring(#remotes.functions)
            App._remoteCountLabels.bindables.Text = tostring(#remotes.bindables)
        end

        App.log(string.format("Found: %d RemoteEvents, %d RemoteFunctions, %d BindableEvents",
            #remotes.events, #remotes.functions, #remotes.bindables), "success")

        if totalRemotes == 0 then
            App.log("No remotes found in this game.", "warning")
            Toast.show("No remote instances found to audit.", "warning")
            App.setScanningState(false)
            App.setProgress(1, "No remotes found")
            return
        end

        App.setProgress(0.2, "Building AI audit prompt...")
        App.log("Building security audit prompt...", "info")
        task.wait(0.1)

        if State.scanCancelled then
            App.setScanningState(false)
            App.setProgress(0, "Cancelled")
            return
        end

        -- Step 2: Build prompt
        local prompt
        local ok2, err2 = pcall(function()
            prompt = Scanner.buildAuditPrompt(remotes)
        end)

        if not ok2 or not prompt then
            App.log("ERROR building prompt: " .. tostring(err2), "error")
            Toast.show("Failed to build audit prompt.", "error")
            App.setScanningState(false)
            App.setProgress(0, "Scan failed")
            return
        end

        local estimatedTokens = math.ceil(#prompt / 4)
        App.log(string.format("Prompt built: ~%d chars (~%d tokens)", #prompt, estimatedTokens), "info")
        App.setProgress(0.35, "Sending to Groq AI... (may take up to 30s)")
        App.log("Sending to Groq API...", "info")

        if State.scanCancelled then
            App.setScanningState(false)
            App.setProgress(0, "Cancelled")
            return
        end

        -- Animate progress during API wait
        local progressConn
        local fakeProgress = 0.35
        progressConn = RunService.Heartbeat:Connect(function(dt)
            if not State.isScanning or State.scanCancelled then
                progressConn:Disconnect()
                return
            end
            fakeProgress = math.min(0.85, fakeProgress + dt * 0.018)
            App.setProgress(fakeProgress, "Waiting for AI response...")
        end)

        -- Step 3: Call Groq
        local findings, apiErr = Scanner.callGroq(State.apiKey, prompt)

        progressConn:Disconnect()

        if State.scanCancelled then
            App.setScanningState(false)
            App.setProgress(0, "Cancelled")
            return
        end

        if apiErr then
            App.log("API ERROR: " .. apiErr, "error")
            Toast.show("AI error: " .. Util.truncate(apiErr, 80), "error")
            App.setScanningState(false)
            App.setProgress(0, "API error")
            return
        end

        if not findings or #findings == 0 then
            App.log("AI returned no findings (game may be secure or empty).", "warning")
            Toast.show("AI found no security issues.", "success")
            App.setScanningState(false)
            App.setProgress(1, "Scan complete — no issues found")
            return
        end

        App.setProgress(0.9, "Processing " .. #findings .. " findings...")
        App.log("Received " .. #findings .. " findings from AI.", "success")

        -- Step 4: Process findings
        local counts = { CRITICAL = 0, HIGH = 0, MEDIUM = 0, LOW = 0, INFO = 0 }
        for _, f in ipairs(findings) do
            -- Validate fields
            f.severity = (SEVERITY_CONFIG[f.severity] and f.severity) or "INFO"
            f.title = f.title or "Unknown Issue"
            f.remote = f.remote or "Unknown"
            f.path = f.path or f.remote
            f.description = f.description or "No description provided."
            f.recommendation = f.recommendation or "Review and fix this issue."
            f.category = f.category or "General"
            f.type = f.type or "RemoteEvent"
            table.insert(State.findings, f)
            local sev = f.severity
            if counts[sev] then counts[sev] = counts[sev] + 1 end
        end

        App.setProgress(1, string.format("Scan complete — %d issues found", #findings))

        local elapsed = Util.formatTime(tick() - State.scanStartTime)
        App.log(string.format("Scan complete in %s. Found: %d CRITICAL, %d HIGH, %d MEDIUM, %d LOW, %d INFO",
            elapsed, counts.CRITICAL, counts.HIGH, counts.MEDIUM, counts.LOW, counts.INFO), "success")
        App.log("=== SCAN ENDED ===", "accent")

        -- Refresh findings tab
        App.refreshFindings()
        App.updateStats()
        App.setScanningState(false)

        local mainMsg = string.format("Scan done: %d findings (%d critical, %d high)",
            #findings, counts.CRITICAL, counts.HIGH)
        local toastKind = counts.CRITICAL > 0 and "error" or (counts.HIGH > 0 and "warning" or "success")
        Toast.show(mainMsg, toastKind)

        -- Auto-switch to findings
        task.delay(1.5, function()
            App.switchTab("findings")
        end)
    end)
end

-- ============================================================
-- LAUNCH
-- ============================================================

local function init()
    -- Safety check for executor environment
    if not request then
        -- Fallback for environments without request
        local warned = false
        local function fakeRequest(opts)
            if not warned then
                warned = true
                warn("[AuditorGui] No 'request' function found. HTTP calls will fail.")
            end
            return { StatusCode = 0, Body = "{}" }
        end
        request = fakeRequest
    end

    pcall(function()
        App.build()
    end)
end

local ok, err = pcall(init)
if not ok then
    warn("[AI Security Auditor] Startup error: " .. tostring(err))
end
