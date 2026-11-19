# BE_Projects
All 4th Year Projects for BE IT Students.

Everyyear a new Directory will be created.


#Relevent Command for pull, push and merge.....
git fetch
git log --oneline HEAD..origin/main # Command A
git log --oneline origin/main..HEAD # Command B
If "A" generates Output		If "B" generates Output		Action
NO							NO							No Action Required	
Yes							NO							git pull
NO							Yes							git push
Yes							Yes							git merge;git push
