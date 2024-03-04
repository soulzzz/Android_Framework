# Git追加修改(例如注释修改)

git add .

git commit --amend     // 修订上一次的提交

git push  origin HEAD:/refs/for/gk6323v100c_p



# Git修改之前几次提交

git log 查看哪笔修改记录 

git rebase -i HEAD~5 查看前5笔

改pick 为Edit 保存

和追加相同 

改完后

git rebase --continue 回到最新的HEAD 

# Git 拉代码 

拉完后git sync 同步代码

# GIt 回退提交

git reset HEAD^

git reset --hard 回退版本

# Git diff

git diff 比较工作区与HEAD之间的不同

git diff --cached 比较暂存区与HEAD之间的不同



# GIt checkout

- ```
  命令git checkout -- readme.txt意思就是，把readme.txt文件在工作区的修改全部撤销，这里有两种情况：
  
  一种是readme.txt自修改后还没有被放到暂存区，现在，撤销修改就回到和版本库一模一样的状态；(上一次的git commit 后,修改readme.txt 但没有执行git add,回到上一次的git commit后的结果)
  
  一种是readme.txt已经添加到暂存区后，又作了修改，现在，撤销修改就回到添加到暂存区后的状态。(修改readme.txt,并且git add,然后又修改了readme.txt, 此时执行git checkout,回到git add 后的状态)
  
  总之，就是让这个文件回到最近一次git commit或git add时的状态。
  ```

- 当执行 **git checkout HEAD .** 或者 **git-checkout HEAD <file>** 命令时，会用 HEAD 指向的 master 分支中的全部或者部分文件替换暂存区和以及工作区中的文件。这个命令也是极具危险性的，因为不但会清除工作区中未提交的改动，也会清除暂存区中未提交的改动。