import os

def main():
    os.system( 'mkdir ./dr_rules' )
    for d in ( 'windows/builtin',
               'windows/process_creation',
               'windows/sysmon', ):
        outDir = d.replace( '/', '_' )
        print( "Creating dir: %s" % ( outDir, ) )
        os.system( 'mkdir ./dr_rules/%s' % ( outDir, ) )
        thisPath = './sigma/rules/%s/' % ( d, )
        for f in os.listdir( thisPath ):
            thisFile = os.path.join( thisPath, f )
            if not os.path.isfile( thisFile ):
                continue
            print( "Process rule %s" % ( thisFile, ) )
            outFile = "./dr_rules/%s/%s" % ( outDir, f )
            os.system( "python3 ./tools/sigmac -t limacharlie -c ./tools/config/limacharlie.yml %s > %s" % ( thisFile, outFile ) )
            if os.path.getsize( outFile ) == 0:
                os.system( 'rm %s' % ( outFile, ) )

if __name__ == "__main__":
    main()