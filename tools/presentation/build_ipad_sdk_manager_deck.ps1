param(
    [string]$Starter = "$env:TEMP\ipad-sdk-manager-deck\ipad-sdk-manager-starter.pptx",
    [string]$Content = "$env:TEMP\ipad-sdk-manager-deck\ipad-deck-content.json",
    [string]$Output = "$(Split-Path -Parent $PSScriptRoot)\..\outputs\IPAd_SDK_Manager_Architecture_and_Usage.pptx",
    [string]$RenderDir = "$env:TEMP\ipad-sdk-manager-deck\rendered"
)

$ErrorActionPreference = 'Stop'

function Color([int]$r, [int]$g, [int]$b) { return $r + ($g * 256) + ($b * 65536) }
$Cobalt = Color 36 87 214
$CobaltDark = Color 25 61 160
$Ink = Color 20 23 26
$Gray = Color 107 114 128
$LightGray = Color 244 246 249
$MidGray = Color 229 231 235
$White = Color 255 255 255
$Orange = Color 217 119 6
$Green = Color 22 130 92
$Font = 'Microsoft YaHei'

function Add-Text($slide, [string]$text, [float]$left, [float]$top, [float]$width, [float]$height, [float]$size = 16, [int]$color = $Ink, [bool]$bold = $false, [int]$align = 1) {
    $shape = $slide.Shapes.AddTextbox(1, $left, $top, $width, $height)
    $shape.TextFrame.MarginLeft = 0
    $shape.TextFrame.MarginRight = 0
    $shape.TextFrame.MarginTop = 0
    $shape.TextFrame.MarginBottom = 0
    $shape.TextFrame.WordWrap = -1
    $shape.TextFrame.AutoSize = 0
    $shape.TextFrame.TextRange.Text = $text
    $shape.TextFrame.TextRange.Font.Name = $Font
    $shape.TextFrame.TextRange.Font.Size = $size
    $shape.TextFrame.TextRange.Font.Color.RGB = $color
    $shape.TextFrame.TextRange.Font.Bold = $(if($bold){-1}else{0})
    $shape.TextFrame.TextRange.ParagraphFormat.Alignment = $align
    $shape.TextFrame2.AutoSize = 0
    $shape.Left = $left
    $shape.Top = $top
    $shape.Width = $width
    $shape.Height = $height
    return $shape
}

function Add-Box($slide, [float]$left, [float]$top, [float]$width, [float]$height, [int]$fill, [int]$line = $MidGray, [float]$radius = 0) {
    $shapeType = $(if($radius -gt 0){5}else{1})
    $shape = $slide.Shapes.AddShape($shapeType, $left, $top, $width, $height)
    $shape.Fill.ForeColor.RGB = $fill
    $shape.Fill.Solid()
    $shape.Line.ForeColor.RGB = $line
    $shape.Line.Weight = 0.75
    return $shape
}

function Add-Line($slide, [float]$x1, [float]$y1, [float]$x2, [float]$y2, [int]$color = $Cobalt, [float]$weight = 1.5) {
    $line = $slide.Shapes.AddLine($x1, $y1, $x2, $y2)
    $line.Line.ForeColor.RGB = $color
    $line.Line.Weight = $weight
    return $line
}

function Clear-Slide($slide) {
    for($i = $slide.Shapes.Count; $i -ge 1; $i--) { $slide.Shapes.Item($i).Delete() }
    $slide.FollowMasterBackground = -1
}

function Add-Frame($slide, $def, [int]$page, [int]$total) {
    Add-Text $slide $def.section.ToUpper() 54 28 300 18 9 $Cobalt $true | Out-Null
    Add-Text $slide $def.title 54 52 852 54 25 $Ink $true | Out-Null
    Add-Line $slide 54 112 906 112 $Ink 0.8 | Out-Null
    Add-Text $slide $def.audiences 670 504 190 14 8 $Gray $false 3 | Out-Null
    Add-Text $slide ("{0:D2} / {1:D2}" -f $page, $total) 866 504 40 14 8 $Cobalt $true 3 | Out-Null
}

function Add-Intro($slide, [string]$text) {
    if([string]::IsNullOrWhiteSpace($text)) { return }
    Add-Text $slide $text 54 124 852 36 11 $Gray $false | Out-Null
}

function Render-Cover($slide, $def) {
    Add-Text $slide $def.kicker 54 48 500 18 9 $Cobalt $true | Out-Null
    Add-Text $slide $def.title 54 118 720 76 36 $Cobalt $true | Out-Null
    Add-Line $slide 54 210 906 210 $Ink 1.2 | Out-Null
    Add-Text $slide $def.subtitle 54 236 780 90 18 $Ink $false | Out-Null
    Add-Text $slide $def.note 54 452 500 22 11 $Gray $false | Out-Null
    Add-Text $slide $def.audiences 710 452 196 22 10 $Cobalt $true 3 | Out-Null
}

function Render-Section($slide, $def, [int]$page, [int]$total) {
    Add-Text $slide $def.section.ToUpper() 54 58 300 18 10 $Cobalt $true | Out-Null
    Add-Text $slide $def.title 54 148 820 74 32 $Cobalt $true | Out-Null
    Add-Line $slide 54 238 906 238 $Ink 1.2 | Out-Null
    Add-Text $slide $def.subtitle 54 268 760 68 16 $Ink $false | Out-Null
    Add-Text $slide $def.audiences 670 504 190 14 8 $Gray $false 3 | Out-Null
    Add-Text $slide ("{0:D2} / {1:D2}" -f $page, $total) 866 504 40 14 8 $Cobalt $true 3 | Out-Null
}

function Render-Agenda($slide, $def, [int]$page, [int]$total) {
    Add-Frame $slide $def $page $total
    $items = @($def.items)
    for($i=0; $i -lt $items.Count; $i++) {
        $row = [math]::Floor($i / 2); $col = $i % 2
        $x = 54 + ($col * 426); $y = 142 + ($row * 108)
        Add-Box $slide $x $y 396 78 $LightGray $MidGray 8 | Out-Null
        $parts = $items[$i] -split '  ', 2
        Add-Text $slide $parts[0] ($x+16) ($y+16) 48 28 18 $Cobalt $true | Out-Null
        Add-Text $slide $parts[1] ($x+72) ($y+16) 300 40 14 $Ink $true | Out-Null
    }
}

function Render-Cards($slide, $def, [int]$page, [int]$total) {
    Add-Frame $slide $def $page $total
    Add-Intro $slide $def.intro
    $cards = @($def.cards); $count = $cards.Count
    $cols = $(if($count -le 4){2}elseif($count -le 6){3}else{4})
    $rows = [math]::Ceiling($count / $cols)
    $gap = 12; $left = 54; $top = 172; $areaW = 852; $areaH = 310
    $w = ($areaW - (($cols - 1) * $gap)) / $cols
    $h = ($areaH - (($rows - 1) * $gap)) / $rows
    for($i=0; $i -lt $count; $i++) {
        $row=[math]::Floor($i/$cols); $col=$i%$cols; $x=$left+$col*($w+$gap); $y=$top+$row*($h+$gap)
        Add-Box $slide $x $y $w $h $LightGray $MidGray 8 | Out-Null
        Add-Box $slide $x $y 5 $h $Cobalt $Cobalt | Out-Null
        Add-Text $slide $cards[$i][0] ($x+16) ($y+14) ($w-28) 25 $(if($cols -eq 4){12}else{14}) $Cobalt $true | Out-Null
        Add-Text $slide $cards[$i][1] ($x+16) ($y+44) ($w-28) ($h-54) $(if($cols -eq 4){9}else{10}) $Ink $false | Out-Null
    }
}

function Render-Flow($slide, $def, [int]$page, [int]$total) {
    Add-Frame $slide $def $page $total
    Add-Intro $slide $def.intro
    $steps=@($def.steps); $count=$steps.Count; $gap=18; $left=54; $top=228; $w=(852-(($count-1)*$gap))/$count; $h=112
    for($i=0;$i -lt $count;$i++) {
        $x=$left+$i*($w+$gap)
        Add-Box $slide $x $top $w $h $(if($i -eq 0 -or $i -eq $count-1){$Cobalt}else{$LightGray}) $(if($i -eq 0 -or $i -eq $count-1){$Cobalt}else{$MidGray}) 8 | Out-Null
        Add-Text $slide ("{0:D2}" -f ($i+1)) ($x+10) ($top+10) 32 18 9 $(if($i -eq 0 -or $i -eq $count-1){$White}else{$Cobalt}) $true | Out-Null
        Add-Text $slide $steps[$i] ($x+10) ($top+38) ($w-20) 62 $(if($count -gt 6){10}else{11}) $(if($i -eq 0 -or $i -eq $count-1){$White}else{$Ink}) $true 2 | Out-Null
        if($i -lt $count-1) {
            $arrow=Add-Line $slide ($x+$w+2) ($top+56) ($x+$w+$gap-2) ($top+56) $Cobalt 1.5
            $arrow.Line.EndArrowheadStyle=3
        }
    }
}

function Render-Layers($slide, $def, [int]$page, [int]$total) {
    Add-Frame $slide $def $page $total
    $layers=@($def.layers); $top=136; $h=62; $gap=8
    for($i=0;$i -lt $layers.Count;$i++) {
        $y=$top+$i*($h+$gap); $offset=$i*22; $x=54+$offset; $w=852-($offset*2)
        Add-Box $slide $x $y $w $h $(if($i -eq 0){$Cobalt}else{$LightGray}) $(if($i -eq 0){$Cobalt}else{$MidGray}) 6 | Out-Null
        Add-Text $slide $layers[$i][0] ($x+16) ($y+13) 145 28 13 $(if($i -eq 0){$White}else{$Cobalt}) $true | Out-Null
        Add-Text $slide $layers[$i][1] ($x+174) ($y+13) ($w-190) 34 11 $(if($i -eq 0){$White}else{$Ink}) $false | Out-Null
    }
}

function Render-Table($slide, $def, [int]$page, [int]$total) {
    Add-Frame $slide $def $page $total
    Add-Intro $slide $def.intro
    $columns=@($def.columns); $rows=@($def.rows); $rowCount=$rows.Count+1; $colCount=$columns.Count
    $top=$(if([string]::IsNullOrWhiteSpace($def.intro)){136}else{170}); $height=310
    $tableShape=$slide.Shapes.AddTable($rowCount,$colCount,54,$top,852,$height)
    $table=$tableShape.Table
    for($c=1;$c -le $colCount;$c++) {
        $cell=$table.Cell(1,$c).Shape
        $cell.Fill.ForeColor.RGB=$Cobalt; $cell.Fill.Solid()
        $cell.TextFrame.TextRange.Text=$columns[$c-1]; $cell.TextFrame.TextRange.Font.Name=$Font; $cell.TextFrame.TextRange.Font.Size=10; $cell.TextFrame.TextRange.Font.Bold=-1; $cell.TextFrame.TextRange.Font.Color.RGB=$White
    }
    for($r=1;$r -le $rows.Count;$r++) {
        for($c=1;$c -le $colCount;$c++) {
            $cell=$table.Cell($r+1,$c).Shape
            $cell.Fill.ForeColor.RGB=$(if($r%2 -eq 0){$White}else{$LightGray}); $cell.Fill.Solid()
            $cell.TextFrame.MarginLeft=6; $cell.TextFrame.MarginRight=6; $cell.TextFrame.MarginTop=3; $cell.TextFrame.MarginBottom=3
            $cell.TextFrame.TextRange.Text=[string]$rows[$r-1][$c-1]; $cell.TextFrame.TextRange.Font.Name=$Font; $cell.TextFrame.TextRange.Font.Size=$(if($rows.Count -ge 7){8.5}else{9.5}); $cell.TextFrame.TextRange.Font.Color.RGB=$Ink
            if($c -eq 1){$cell.TextFrame.TextRange.Font.Bold=-1; $cell.TextFrame.TextRange.Font.Color.RGB=$CobaltDark}
        }
    }
}

function Render-Timeline($slide, $def, [int]$page, [int]$total) {
    Add-Frame $slide $def $page $total
    $items=@($def.milestones); $y=244
    Add-Line $slide 120 $y 840 $y $Cobalt 3 | Out-Null
    for($i=0;$i -lt $items.Count;$i++) {
        $x=140+$i*330
        $dot=$slide.Shapes.AddShape(9,$x-10,$y-10,20,20); $dot.Fill.ForeColor.RGB=$Cobalt; $dot.Fill.Solid(); $dot.Line.Visible=0
        Add-Text $slide $items[$i][0] ($x-88) 152 176 44 14 $Cobalt $true 2 | Out-Null
        Add-Box $slide ($x-108) 278 216 128 $LightGray $MidGray 8 | Out-Null
        Add-Text $slide $items[$i][1] ($x-92) 296 184 92 10 $Ink $false | Out-Null
    }
}

function Render-Closing($slide, $def) {
    Add-Text $slide "SUMMARY" 54 52 300 18 10 $Cobalt $true | Out-Null
    Add-Text $slide $def.title 54 132 820 116 30 $Cobalt $true | Out-Null
    Add-Line $slide 54 268 906 268 $Ink 1.2 | Out-Null
    Add-Text $slide $def.subtitle 54 298 810 86 16 $Ink $false | Out-Null
    Add-Text $slide $def.note 54 456 500 20 9 $Gray $false | Out-Null
    Add-Text $slide $def.audiences 700 456 206 20 9 $Cobalt $true 3 | Out-Null
}

$defs = Get-Content -Raw -Encoding UTF8 $Content | ConvertFrom-Json
$outDir = Split-Path -Parent $Output
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
New-Item -ItemType Directory -Force -Path $RenderDir | Out-Null

$ppt = New-Object -ComObject PowerPoint.Application
$ppt.Visible = -1
$presentation = $ppt.Presentations.Open($Starter, $false, $false, $false)
try {
    if($presentation.Slides.Count -ne $defs.Count) { throw "Slide count mismatch: $($presentation.Slides.Count) vs $($defs.Count)" }
    for($i=1;$i -le $defs.Count;$i++) {
        $slide=$presentation.Slides.Item($i); $def=$defs[$i-1]
        Clear-Slide $slide
        switch([string]$def.type) {
            'cover' { Render-Cover $slide $def }
            'agenda' { Render-Agenda $slide $def $i $defs.Count }
            'section' { Render-Section $slide $def $i $defs.Count }
            'cards' { Render-Cards $slide $def $i $defs.Count }
            'flow' { Render-Flow $slide $def $i $defs.Count }
            'layers' { Render-Layers $slide $def $i $defs.Count }
            'table' { Render-Table $slide $def $i $defs.Count }
            'timeline' { Render-Timeline $slide $def $i $defs.Count }
            'closing' { Render-Closing $slide $def }
            default { throw "Unknown layout type: $($def.type)" }
        }
    }
    $presentation.SaveAs($Output,24)
    $presentation.Export($RenderDir,'PNG',1600,900)
} finally {
    $presentation.Close()
    $ppt.Quit()
    [System.Runtime.InteropServices.Marshal]::ReleaseComObject($presentation) | Out-Null
    [System.Runtime.InteropServices.Marshal]::ReleaseComObject($ppt) | Out-Null
    [GC]::Collect(); [GC]::WaitForPendingFinalizers()
}

Write-Output "output=$Output"
Write-Output "slides=$($defs.Count)"
Write-Output "renders=$((Get-ChildItem $RenderDir -Filter '*.PNG').Count)"
