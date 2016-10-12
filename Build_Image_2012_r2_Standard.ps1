Import-Module C:\Users\Administrator\code\windows-openstack-imaging-tools\WinImageBuilder.psm1

# The disk format can be: VHD, VHDX, QCow2, VMDK or RAW
$virtualDiskPath = "c:\Images\Server_2012_R2_Standard.qcow2"
# This is the content of your Windows ISO
$wimFilePath = "C:\Repo\OS\WinSvr2012R2_RPC\OEM\sources\install.wim"
# Optionally, if you target KVM
$virtIOISOPath = "C:\ISO\virtio-win-0.1.126.iso"

# Check what images are supported in this Windows ISO
#$images = Get-WimFileImagesInfo -WimFilePath $wimFilePath
# Select the first one
#$image = $images[0]
#$image

# The product key is optional
$productKey = “D2N9P-3P6X9-2R39C-7RTCD-MDVJX"

# Add -InstallUpdates for the Windows updates (it takes longer and requires
# more space but it's highly recommended)
New-WindowsCloudImage -WimFilePath $wimFilePath -ImageName "Windows Server 2012 R2 SERVERSTANDARD" `
-VirtualDiskFormat QCow2 -VirtualDiskPath $virtualDiskPath `
-SizeBytes 30GB -ProductKey $productKey -VirtIOISOPath $virtIOISOPath -InstallUpdates 