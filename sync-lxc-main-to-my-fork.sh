### This is set-up for making a public layman for testing by non spike-  general Gentoo use Abuse and Etc..
### you can always edit this to keep your own fork In sync, 
##git remote set-url --push origin https://github.com/Sabayon-Labs/spike-overlay/.git  git@github.com:Spike-Pentesting/App-witchcraft.git
## reused to sync github repos on the EZ...
git remote add origin https://github.com/necrose99/lxc.git
git remote add upstream https://github.com/lxc/lxc.git
git checkout master
git fetch upstream
git merge upstream/master
git push origin
