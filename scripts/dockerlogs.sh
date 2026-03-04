OUTFILE=matrix_stack_logs.txt

docker ps --filter "label=com.docker.compose.project=matrix" --format "{{.Names}}" | while read c; do
    echo "===============================" >> $OUTFILE
    echo "CONTAINER: $c" >> $OUTFILE
    echo "===============================" >> $OUTFILE
    docker logs --tail 150 $c >> $OUTFILE 2>&1
    echo "" >> $OUTFILE
done
