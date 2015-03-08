THIS file is temporary 

more of a <i><b>noted TOO DO LIST. </b></i>

I have borrowed some code elements from 

https://github.com/adrienthebo/sabayon-chroot-builder

for https://github.com/necrose99/lxc/blob/master/templates/lxc-sabayon.in

https://github.com/necrose99/lxc/blob/master/templates/lxc-spike-pentesting.in (lxc-sabayon.in) with a few extra toys.

https://github.com/necrose99/lxc/blob/master/templates/lxc-pentoo.in  stuff in thier however needs <b> Orginized and Decrufted</b>
I'm a touch tired atm I'll have at it again hopefully by Friday the 13th march '15 I'll have it more done at the lattest.

adrienthebo's code has recyclability and can be called or from other scripts as functions wich is good. 
my bash is low/rusty anyhow, but aiming at the longer term , and the ability to chain call is usefull IE rUBY , vagrant chef or on uper abstraction layers.


main rub it storing values from lxc-gentoo.in  and making sure they are before the sript and failsafe copy to a new value.
{rootfs}="${SAB_rootfs}"  keeping {rootfs}  and runing with it after LXC exits gentoo lxc build cycle is prerable however 
better safe than sorry so #FAILSAFE it is. 
the IDEA is to Embed lxc-gentoo.in Sabayon script then keep a few values , then chroot into the lxc container add on layman equo and repo's
then update system etc.  Spike just tack on our repos as addon functions. and our entropy repo/s 

Pentoo likewise build layman pentoo opts, and update system with eslect Cpu spec, pentoo binary profile so update cycle wont take forever.
