Trying to use git subrepo (https://github.com/ingydotnet/git-subrepo)

# Short install on linux
git clone https://github.com/ingydotnet/git-subrepo /home/$USER/bin/git-subrepo
echo 'source /home/$USER/bin/git-subrepo/.rc' >> ~/.bashrc

git clone --recursive-submodules ssh://git@code.ceptro.br:7999/simet2/simet-agent-unix.git