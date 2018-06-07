### TODO - update readme

Using git subrepo (https://github.com/ingydotnet/git-subrepo)

# Short install on linux
git clone https://github.com/ingydotnet/git-subrepo /home/$USER/bin/git-subrepo
echo 'source /home/$USER/bin/git-subrepo/.rc' >> ~/.bashrc

# Clone example

```sh
git subrepo clone ${GIT_URL} -b ${TAG} -f
# git subrepo clone ssh://git@code.ceptro.br:7999/simet2/tcp-client-c.git tcp-client-c -b v0.1.0 -f
```
