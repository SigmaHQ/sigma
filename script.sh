for i in $(find . -type f -iname *.yml | grep -i suspicious);
do
	DIR=$(dirname $i)
    NEW_NAME=$(basename $i | sed 's/suspicious/susp/')
	git mv $i $DIR/$NEW_NAME
done