IF "%APPVEYOR_REPO_TAG_NAME%"=="" (
Set suffix=%APPVEYOR_BUILD_NUMBER%
) ELSE (
Set suffix=""
ECHO ^<Project^>^<Import Project=^"./releasenotes/%APPVEYOR_REPO_TAG_NAME%.props^" /^>^<PropertyGroup^>^<VersionPrefix^>%APPVEYOR_REPO_TAG_NAME%^</VersionPrefix^>^</PropertyGroup^>^</Project^> > version.props
)
