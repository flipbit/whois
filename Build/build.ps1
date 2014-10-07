properties { 
  $zipFileName = "Whois.zip"
  $majorVersion = "1.0"
  $majorWithReleaseVersion = "1.0.0"
  $version = GetVersion $majorWithReleaseVersion
  $buildNuGet = $true
  $treatWarningsAsErrors = $false
  
  $baseDir  = resolve-path ..
  $buildDir = "$baseDir\Build"
  $sourceDir = "$baseDir"
  $toolsDir = "$baseDir\Tools"
  $docDir = "$baseDir\Docs"
  $releaseDir = "$baseDir\Release"
  $workingDir = "$baseDir\Working"
  $builds = @(
    @{Name = "Whois"; TestsName = "Whois.Tests"; Constants=""; FinalDir="Net45"; NuGetDir = "net45"; Framework="net-4.5"},
    @{Name = "Whois.Net40"; TestsName = "Whois.Tests.Net40"; Constants=""; FinalDir="Net40"; NuGetDir = "net40"; Framework="net-4.0"},
    @{Name = "Whois.Net35"; TestsName = "Whois.Tests.Net35"; Constants=""; FinalDir="Net35"; NuGetDir = "net35"; Framework="net-3.5"},
    @{Name = "Whois.Net20"; TestsName = "Whois.Tests.Net20"; Constants=""; FinalDir="Net20"; NuGetDir = "net20"; Framework="net-2.0"}
  )
}

$framework = '4.0x86'

task default -depends Test

# Ensure a clean working directory
task Clean {
  Set-Location $baseDir
  
  if (Test-Path -path $workingDir)
  {
    Write-Output "Deleting Working Directory"
    
    del $workingDir -Recurse -Force
  }
  
  New-Item -Path $workingDir -ItemType Directory
}

# Build each solution, optionally signed
task Build -depends Clean { 
  Write-Host -ForegroundColor Green "Updating assembly version"
  Write-Host
  Update-AssemblyInfoFiles $sourceDir ($majorVersion + '.0.0') $version

  foreach ($build in $builds)
  {
    $name = $build.Name
    $finalDir = $build.FinalDir

    Write-Host -ForegroundColor Green "Building " $name

    Write-Host
    Write-Host "Restoring"
    exec { .\Tools\NuGet\NuGet.exe restore ".\$name.sln" | Out-Default } "Error restoring $name"

    Write-Host
    Write-Host "Building"
    exec { msbuild "/t:Clean;Rebuild" /p:Configuration=Release "/p:Platform=Any CPU" /p:OutputPath=bin\Release\$finalDir\ "/p:TreatWarningsAsErrors=$treatWarningsAsErrors" "/p:VisualStudioVersion=12.0" (GetConstants $build.Constants) ".\$name.sln" | Out-Default } "Error building $name"
  }
}

# Optional build documentation, add files to final zip
task Package -depends Build {
  foreach ($build in $builds)
  {
    $name = $build.TestsName
    $finalDir = $build.FinalDir
    
    robocopy "$sourceDir\Whois\bin\Release\$finalDir" $workingDir\Package\Bin\$finalDir *.dll *.pdb *.xml /NP /XO /XF *.CodeAnalysisLog.xml | Out-Default
  }
  
  if ($buildNuGet)
  {
    New-Item -Path $workingDir\NuGet -ItemType Directory    
    Copy-Item -Path "$buildDir\Whois.nuspec" -Destination $workingDir\NuGet\Whois.nuspec -recurse

    Copy-Item -Path "$sourceDir\Whois\Readme.txt" -Destination $workingDir\NuGet\Readme.txt -recurse
    
    foreach ($build in $builds)
    {
      if ($build.NuGetDir)
      {
        $name = $build.TestsName
        $finalDir = $build.FinalDir
        $frameworkDirs = $build.NuGetDir.Split(",")
        
        foreach ($frameworkDir in $frameworkDirs)
        {
          robocopy "$sourceDir\Whois\bin\Release\$finalDir" $workingDir\NuGet\lib\$frameworkDir *.dll *.pdb *.xml /NP /XO /XF *.CodeAnalysisLog.xml | Out-Default
        }
      }
    }
  
    robocopy $sourceDir\Whois $workingDir\NuGet\src *.cs /S /NP /XD Whois.Tests /XD ".git" obj | Out-Default

    exec { .\Tools\NuGet\NuGet.exe pack $workingDir\NuGet\Whois.nuspec -Symbols }
    move -Path .\*.nupkg -Destination $workingDir\NuGet
  }
  
  Copy-Item -Path $docDir\readme.txt -Destination $workingDir\Package\
  Copy-Item -Path $docDir\license.txt -Destination $workingDir\Package\

  # exclude package directories but keep packages\repositories.config
  $packageDirs = gci $sourceDir\packages | where {$_.PsIsContainer} | Select -ExpandProperty Name

  robocopy $sourceDir\Whois $workingDir\Package\Source\Src /MIR /NP /XD bin obj TestResults AppPackages $packageDirs /XF *.suo *.user | Out-Default
  robocopy $buildDir $workingDir\Package\Source\Build /MIR /NP /XF runbuild.txt | Out-Default
  robocopy $docDir $workingDir\Package\Source\Doc /MIR /NP | Out-Default
  robocopy $toolsDir $workingDir\Package\Source\Tools /MIR /NP | Out-Default
  
  exec { .\Tools\7-zip\7za.exe a -tzip $workingDir\$zipFileName $workingDir\Package\* | Out-Default } "Error zipping"
}

# Unzip package to a location
task Deploy -depends Package {
  exec { .\Tools\7-zip\7za.exe x -y "-o$workingDir\Deployed" $workingDir\$zipFileName | Out-Default } "Error unzipping"
}

# Run tests on deployed files
task Test -depends Deploy {
  foreach ($build in $builds)
  {
    $name = $build.TestsName
    if ($name -ne $null)
    {
        $finalDir = $build.FinalDir
        $framework = $build.Framework
        
        Write-Host -ForegroundColor Green "Copying test assembly $name to deployed directory"
        Write-Host
        robocopy ".\Whois.Tests\bin\Release\$finalDir" $workingDir\Deployed\Bin\$finalDir /MIR /NP /XO | Out-Default
        
        Copy-Item -Path ".\Whois.Tests\bin\Release\$finalDir\Whois.Tests.dll" -Destination $workingDir\Deployed\Bin\$finalDir\

        Write-Host -ForegroundColor Green "Running tests " $name
        Write-Host
        exec { .\Tools\NUnit\nunit-console.exe "$workingDir\Deployed\Bin\$finalDir\Whois.Tests.dll" /framework=$framework /xml:$workingDir\$name.xml | Out-Default } "Error running $name tests"
    }
  }
}

function GetConstants($constants, $includeSigned)
{
  $signed = switch($includeSigned) { $true { ";SIGNED" } default { "" } }

  return "/p:DefineConstants=`"CODE_ANALYSIS;TRACE;$constants$signed`""
}

function GetVersion($majorVersion)
{
    return "1.0"
}

function Update-AssemblyInfoFiles ([string] $sourceDir, [string] $assemblyVersionNumber, [string] $fileVersionNumber)
{
    $assemblyVersionPattern = 'AssemblyVersion\("[0-9]+(\.([0-9]+|\*)){1,3}"\)'
    $fileVersionPattern = 'AssemblyFileVersion\("[0-9]+(\.([0-9]+|\*)){1,3}"\)'
    $assemblyVersion = 'AssemblyVersion("' + $assemblyVersionNumber + '")';
    $fileVersion = 'AssemblyFileVersion("' + $fileVersionNumber + '")';
    
    Get-ChildItem -Path $sourceDir -r -filter AssemblyInfo.cs | ForEach-Object {
        
        $filename = $_.Directory.ToString() + '\' + $_.Name
        Write-Host $filename
        $filename + ' -> ' + $version
    
        (Get-Content $filename) | ForEach-Object {
            % {$_ -replace $assemblyVersionPattern, $assemblyVersion } |
            % {$_ -replace $fileVersionPattern, $fileVersion }
        } | Set-Content $filename
    }
}