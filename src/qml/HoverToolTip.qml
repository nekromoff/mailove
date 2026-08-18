// SPDX-License-Identifier: GPL-3.0-or-later

import QtQuick
import QtQuick.Window
import QtQuick.Controls as QQC2
import org.kde.kirigami as Kirigami

// A tooltip that shows up next to the pointer instead of centred over the item
// it belongs to. The stock placement (horizontally centred, just above the
// item) is fine for a toolbutton, but for a full-width label — the status
// breadcrumb, the sender-authentication badges — it lands in the middle of the
// window, nowhere near the cursor that asked for it.
QQC2.ToolTip {
    id: tip

    // The handler that reports the pointer; drives both when we show and where.
    required property HoverHandler hover

    // Authentication headers are a wall of "method=result" pairs and the reader
    // is looking for exactly one thing in them, so let callers make the failing
    // fields stand out.
    property bool markFailures: false

    // This text is sender-adjacent — Authentication-Results echoes envelope
    // addresses, which carry '<' and '&' — so it must never be interpreted as
    // markup of its own. Everything is escaped; only the <b> and <br> we add
    // here survive.
    readonly property string displayText: {
        const escape = s => s.replace(/&/g, "&amp;")
                             .replace(/</g, "&lt;")
                             .replace(/>/g, "&gt;")
        // An explainer line — "DKIM: Does …? Yes" — gets its acronym and its
        // answer words bolded, so the eye can walk the tooltip on the bold
        // alone: which check, what came of it. Applied to escaped text; the
        // pattern's anchors keep it off anything sender-shaped.
        const boldExplainer = line => line
            .replace(/^(SPF|DKIM|DMARC|ARC|COMPAUTH):/,
                     "<b>$1</b>:")
            .replace(/\?( (?:Yes|No|Warning|Not checked)(?:, (?:Yes|No|Warning|Not checked))*)$/,
                     "?<b>$1</b>")
        if (!tip.markFailures)
            return escape(tip.text).split("\n").map(boldExplainer).join("<br>")
        // Bold the whole failing field, not just the verdict word: the part
        // worth reading is the "(p=none dis=none) header.from=…" that follows
        // it. Split before escaping — escaping introduces ';' via "&amp;",
        // which would otherwise chop a field in half.
        return tip.text.split("\n").map(line =>
            boldExplainer(tip.splitFields(line).map(field => {
                // Only a *leading* method=result is a verdict. Anything later in
                // the field echoes sender-supplied data, so a sender could put
                // "dkim=fail" in their own envelope address and pick which
                // field we highlight. Same rule the condensed badge follows.
                // "softfail" and "permerror" are failures too.
                const fail = /^\s*(?:dkim|spf|dmarc|arc|iprev)\s*=\s*\w*(?:fail|error)\b/i
                if (!fail.test(field))
                    return escape(field)
                // Keep the surrounding whitespace out of the bold run so the
                // field separators stay evenly spaced.
                const [, lead, body, trail] = /^(\s*)([\s\S]*?)(\s*)$/.exec(field)
                return lead + "<b>" + escape(body) + "</b>" + trail
            }).join(";"))
        ).join("<br>") // StyledText ignores bare newlines
    }

    // Split an Authentication-Results line into its ';'-delimited fields,
    // ignoring separators inside (comments) and "quoted strings" — a verdict
    // like `dmarc=fail (p=none; dis=none) header.from=x` is one field, and
    // splitting it naively would leave half of it unmarked.
    function splitFields(line) {
        let fields = []
        let start = 0, depth = 0, quoted = false
        for (let i = 0; i < line.length; ++i) {
            const c = line[i]
            if (quoted) {
                if (c === "\\")
                    ++i
                else if (c === '"')
                    quoted = false
            } else if (c === '"') {
                quoted = true
            } else if (c === "(") {
                ++depth
            } else if (c === ")") {
                depth = Math.max(0, depth - 1)
            } else if (c === ";" && depth === 0) {
                fields.push(line.substring(start, i))
                start = i + 1
            }
        }
        fields.push(line.substring(start))
        return fields
    }

    // Shown the moment the pointer is over the item, with no delay — which
    // is what the rest of the app does, whether or not it looks deliberate:
    // the spam and authentication marks in the message list are attached
    // QQC2.ToolTips whose `visible` is bound to a HoverHandler, and a bound
    // `visible` bypasses ToolTip's own `delay`. So every tooltip in mailove
    // that answers "what is this mark" appears at once, and these have to as
    // well or the two feel like different applications.
    // Explicitly zero. org.kde.desktop gives ToolTip a default delay, and it
    // applies to this instance's own `visible` too — so binding visibility to
    // the hover handler still waited it out. The attached ToolTips on the spam
    // and authentication marks in the list do not go through it, which is why
    // those appear at once and these did not.
    delay: 0
    visible: tip.hover.hovered && tip.text.length > 0

    // Place the popup ourselves rather than letting Popup's own margin handling
    // shove an overflowing tooltip back inside the window: near the right edge
    // that slides it all the way to the far side of the screen, nowhere near
    // the cursor. Flipping to the other side of the pointer keeps it in reach.
    //
    // A binding, not a one-shot placement, so the tooltip keeps tracking the
    // pointer: it re-runs on every move, and on the implicit size settling
    // after the content lays out.
    readonly property point placement: {
        const item = tip.parent
        if (!item || !item.Window.window)
            return Qt.point(0, 0)
        // Enough of a gap that the popup does not land under the pointer:
        // covering the hovered item would take the hover away and flicker the
        // tooltip straight back off.
        const gap = Kirigami.Units.gridUnit
        const edge = tip.margins
        const w = tip.implicitWidth
        const h = tip.implicitHeight
        const pointer = item.mapToItem(null, tip.hover.point.position.x,
                                             tip.hover.point.position.y)

        let px = pointer.x + gap
        if (px + w + edge > item.Window.width)
            px = pointer.x - gap - w // to the left of the cursor instead
        let py = pointer.y + gap
        if (py + h + edge > item.Window.height)
            py = pointer.y - gap - h // above the cursor instead

        // A tooltip wider than the window still has to start somewhere.
        px = Math.max(edge, Math.min(px, item.Window.width - w - edge))
        py = Math.max(edge, Math.min(py, item.Window.height - h - edge))

        return item.mapFromItem(null, px, py)
    }

    x: tip.placement.x
    y: tip.placement.y

    // Same shape as the org.kde.desktop tooltip's own content item, kept
    // because we have to replace it to get StyledText: the wrapper caps the
    // width that the popup asks for, onLineLaidOut caps the text itself.
    contentItem: Item {
        implicitWidth: Math.min(tipLabel.maxTextLength, tipLabel.contentWidth)
        implicitHeight: tipLabel.implicitHeight

        QQC2.Label {
            id: tipLabel

            readonly property double maxTextLength: Kirigami.Units.gridUnit * 20

            text: tip.displayText
            textFormat: Text.StyledText
            wrapMode: Text.Wrap
            font: tip.font
            color: Kirigami.Theme.textColor
            Kirigami.Theme.colorSet: tip.Kirigami.Theme.colorSet
            Kirigami.Theme.inherit: false
            onLineLaidOut: line => {
                if (line.implicitWidth > maxTextLength)
                    line.width = maxTextLength
            }
        }
    }
}
